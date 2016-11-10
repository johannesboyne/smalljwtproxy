package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	jwtr "github.com/dgrijalva/jwt-go/request"
	"github.com/julienschmidt/httprouter"
)

// Proxy proxy config
type Proxy struct {
	Connect    FromTo          `json:"connect"`
	Routes     []AccessControl `json:"routes"`
	Collection map[string]AccessControl
}

// JWTConfig configuration struct
type JWTConfig struct {
	Proxies []Proxy `json:"proxies"`
}

// FromTo definition
type FromTo struct {
	From         string
	To           string
	HeaderPrefix string `json:"header-prefix"`
}

// AccessControl defines allow / deny and open pathes
type AccessControl struct {
	Route string           `json:"route"`
	Allow AccessDefinition `json:"allow"`
}

// JWT Claims
type claim struct {
	Key   string
	Value []string
}

// AccessDefinition access definitions
type AccessDefinition struct {
	Method       []string `json:"method"`
	Open         bool     `json:"open"`
	Claims       []claim  `json:"claims"`
	Cachecontrol string   `json:"cachecontrol"`
}

// Apply host and header values
func sameHostSameHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for h := range r.Header {
			r.Header.Set(h, r.Header.Get(h))
		}
		r.Host = r.URL.Host
		handler.ServeHTTP(w, r)
	})
}

// Add CORS Headers
func addCORSHeaders(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, *http.Request) {
	logger.Debugf("[DEBUG] CORS Headers added")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, HEAD, OPTIONS")
	if len(r.Header["Access-Control-Request-Headers"]) > 0 {
		allowHeadersString := ""
		for _, header := range r.Header["Access-Control-Request-Headers"] {
			allowHeadersString += header + ","
		}
		w.Header().Set("Access-Control-Allow-Headers", allowHeadersString)
	}
	return w, r
}

// Add Caching Headers
func addCachingHeaders(w http.ResponseWriter, r *http.Request, proxyConfig *Proxy) (http.ResponseWriter, *http.Request) {
	if len(proxyConfig.Collection[r.Method+r.URL.String()].Allow.Cachecontrol) > 0 {
		w.Header().Set("Cache-Control", proxyConfig.Collection[r.Method+r.URL.String()].Allow.Cachecontrol)
	}

	return w, r
}

func easyJWT(handler http.Handler, routeConfig AccessControl, headerPrefix string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if routeConfig.Allow.Open == true {
			handler.ServeHTTP(w, r)
			return
		}
		tokenString, err := jwtr.HeaderExtractor{"Authorization"}.ExtractToken(r)
		if err != nil {
			w.WriteHeader(401)
			return
		}
		authHeader := strings.Split(tokenString, "Bearer ")
		tokenString = authHeader[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		if err != nil {
			logger.Infof("[INFO] ACCESS DENIED: Error %v\n", err)
			w.WriteHeader(401)
		} else {
			v := reflect.ValueOf(token.Claims)
			i := v.Interface()
			a := i.(jwt.MapClaims)
			for h, m := range a {
				logger.Debugf("[DEBUG] set %s%v: %v", headerPrefix, h, m)
				r.Header.Set(headerPrefix+h, fmt.Sprintf("%v", m))
			}
			found := false
			potentialErrorMsg := ""
			for _, claim := range routeConfig.Allow.Claims {
				for h, m := range a {
					potentialErrorMsg += fmt.Sprintf("[%v]%v\n", h, m)
					if claim.Key == h {
						for _, v := range claim.Value {
							potentialErrorMsg += fmt.Sprintf("\t check: %v\n", v)
							if m == v {
								found = true
							}
						}
					}
				}
			}
			if found == false {
				logger.Infof("[INFO] ACCESS DENIED: Error: No matching K/V in claims\n%s\n", potentialErrorMsg)
				w.WriteHeader(401)
				return
			}
		}
		handler.ServeHTTP(w, r)
	}
}

// Build all HTTP Methods
func httpMethodBuilder(m string, ac AccessControl, handler http.Handler, router *httprouter.Router, status string, url string, proxyConfig *Proxy) {
	logger.Debugf("[DEBUG] LINK:", m, url)
	switch m {
	case "GET":
		router.GET(ac.Route, easyJWT(handler, ac, proxyConfig.Connect.HeaderPrefix))
	case "POST":
		router.POST(ac.Route, easyJWT(handler, ac, proxyConfig.Connect.HeaderPrefix))
	case "PUT":
		router.PUT(ac.Route, easyJWT(handler, ac, proxyConfig.Connect.HeaderPrefix))
	case "DELETE":
		router.DELETE(ac.Route, easyJWT(handler, ac, proxyConfig.Connect.HeaderPrefix))
	case "HEAD":
		router.HEAD(ac.Route, easyJWT(handler, ac, proxyConfig.Connect.HeaderPrefix))
	}
	// always OPTIONS
	if h, _, _ := router.Lookup("OPTIONS", ac.Route); h == nil {
		logger.Debugf("[DEBUG] LINK: OPTIONS", url)
		router.OPTIONS(ac.Route, func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			logger.Debugf("[DEBUG] set cors", r.URL)
			w, r = addCORSHeaders(w, r)
			w.Write([]byte(""))
			return
		})
	}

}

// Map routes and methods
func mapper(handler http.Handler, url url.URL, proxyConfig *Proxy) *httprouter.Router {
	router := httprouter.New()
	if proxyConfig.Connect.To == url.Host {
		for _, r := range proxyConfig.Routes {
			// link allow methods
			if r.Allow.Method != nil {
				for _, m := range r.Allow.Method {
					httpMethodBuilder(m, r, handler, router, "allow", r.Route, proxyConfig)
				}
			}
		}
	}
	return router
}

// NewSingleHostReverseProxy is cool
func NewSingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = ""
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}
	return &httputil.ReverseProxy{Director: director}
}

// NewReverser creates a new reverser type
func NewReverser(host string, port string, proxyConf *Proxy) *Reverser {
	rpURL, err := url.Parse(host + port)
	if err != nil {
		logger.Fatalf("%+v\n", err)
	}
	// initialize our reverse proxy
	reverseProxy := NewSingleHostReverseProxy(rpURL)
	// wrap that proxy with our sameHostSameHeaders function
	singleHosted := mapper(reverseProxy, *rpURL, proxyConf)
	rev := Reverser{reverseProxy, singleHosted}
	return &rev
}

// Reverser Is a JWT reverse proxy
type Reverser struct {
	Proxy *httputil.ReverseProxy
	Host  *httprouter.Router
}
