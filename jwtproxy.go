package main

import (
	"fmt"
	"log"
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
	Connect FromTo          `json:"connect"`
	Routes  []AccessControl `json:"routes"`
}

// JWTConfig The configuration struct
type JWTConfig struct {
	Proxies    []Proxy `json:"proxies"`
	Collection map[string]AccessControl
}

// FromTo definition
type FromTo struct {
	From string
	To   string
}

// AccessControl defines allow / deny and open pathes
type AccessControl struct {
	Route string           `json:"route"`
	Allow AccessDefinition `json:"allow"`
}

type claim struct {
	Key   string
	Value []string
}

// AccessDefinition access definitions
type AccessDefinition struct {
	Method []string `json:"method"`
	Open   bool     `json:"open"`
	Claims []claim  `json:"claims"`
}

func sameHostSameHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for h := range r.Header {
			r.Header.Set(h, r.Header.Get(h))
		}
		for h := range w.Header() {
			w.Header().Set(h, r.Header.Get(h))
		}

		r.Host = r.URL.Host

		handler.ServeHTTP(w, r)
	})
}

func validateJWT(handler http.Handler, proxyConfig JWTConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("CHECK:", r.URL.String(), r.Method)
		tokenString, err := jwtr.HeaderExtractor{"Authorization"}.ExtractToken(r)
		authHeader := strings.Split(tokenString, "Bearer ")

		if proxyConfig.Collection[r.Method+r.URL.String()].Allow.Open == true {
			log.Println("No JWT or Open route:", r.URL.String())
			handler.ServeHTTP(w, r)
			return
		}

		if err != nil || len(authHeader) <= 1 {
			log.Printf("ACCESS DENIED: No Authorization Bearer, %v\n", err)
			w.WriteHeader(401)
			return
		}
		tokenString = authHeader[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		if err != nil {
			log.Printf("ACCESS DENIED: Error %v\n", err)
			w.WriteHeader(401)
		} else {

			v := reflect.ValueOf(token.Claims)
			i := v.Interface()
			a := i.(jwt.MapClaims)

			if len(proxyConfig.Collection[r.Method+r.URL.String()].Allow.Method) > 0 {
				found := false
				potentialErrorMsg := ""
				for _, claim := range proxyConfig.Collection[r.Method+r.URL.String()].Allow.Claims {
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
					log.Printf("ACCESS DENIED: Error: No matching K/V in claims\n%s\n", potentialErrorMsg)
					w.WriteHeader(401)
					return
				}
			}

			for h, m := range a {
				r.Header.Set("X-Croove-Session-"+h, fmt.Sprintf("%v", m))
			}

			handler.ServeHTTP(w, r)
		}
	})
}

func httpMethodBuilder(m string, ac AccessControl, handler http.Handler, router *httprouter.Router, status string, url string, proxyConfig JWTConfig) {
	log.Println("LINK:", m, url)
	switch m {
	case "GET":
		router.GET(ac.Route, func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			proxyConfig.Collection[m+r.URL.String()] = ac
			r.Header.Set("X-Croove-Session-Anonymous", status)
			handler.ServeHTTP(w, r)
		})
	case "POST":
		router.POST(ac.Route, func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			proxyConfig.Collection[m+r.URL.String()] = ac
			r.Header.Set("X-Croove-Session-Anonymous", status)
			handler.ServeHTTP(w, r)
		})
	case "PUT":
		router.PUT(ac.Route, func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			proxyConfig.Collection[m+r.URL.String()] = ac
			r.Header.Set("X-Croove-Session-Anonymous", status)
			handler.ServeHTTP(w, r)
		})
	case "DELETE":
		router.DELETE(ac.Route, func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			proxyConfig.Collection[m+r.URL.String()] = ac
			r.Header.Set("X-Croove-Session-Anonymous", status)
			handler.ServeHTTP(w, r)
		})
	case "HEAD":
		router.HEAD(ac.Route, func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
			proxyConfig.Collection[m+r.URL.String()] = ac
			r.Header.Set("X-Croove-Session-Anonymous", status)
			handler.ServeHTTP(w, r)
		})
	}
}

func mapper(handler http.Handler, url url.URL, proxyConfig JWTConfig) *httprouter.Router {
	router := httprouter.New()

	for _, p := range proxyConfig.Proxies {
		if p.Connect.To == url.Host {
			for _, r := range p.Routes {
				// link allow methods
				if r.Allow.Method != nil {
					for _, m := range r.Allow.Method {
						httpMethodBuilder(m, r, handler, router, "allow", r.Route, proxyConfig)
					}
				}
			}
		}
	}

	return router
}

// NewReverser creates a new reverser type
func NewReverser(host string, port string, proxyConf JWTConfig) *Reverser {
	rpURL, err := url.Parse(host + port)
	if err != nil {
		log.Fatal(err)
	}

	// initialize our reverse proxy
	reverseProxy := httputil.NewSingleHostReverseProxy(rpURL)
	// wrap that proxy with our sameHostSameHeaders function
	singleHosted := mapper(validateJWT(sameHostSameHeaders(reverseProxy), proxyConf), *rpURL, proxyConf)

	rev := Reverser{reverseProxy, singleHosted}
	return &rev
}

// Reverser Is a JWT reverse proxy
type Reverser struct {
	Proxy *httputil.ReverseProxy
	Host  *httprouter.Router
}
