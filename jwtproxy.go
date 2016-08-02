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
)

func sameHostSameHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for h := range r.Header {
			r.Header.Set(h, r.Header.Get(h))
		}
		for h := range w.Header() {
			w.Header().Set(h, r.Header.Get(h))
		}

		r.Host = r.URL.Host

		for a := range r.Header {
			log.Println(a)
		}
		handler.ServeHTTP(w, r)
	})
}

func validateJWT(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := jwtr.HeaderExtractor{"Authorization"}.ExtractToken(r)
		authHeader := strings.Split(tokenString, "Bearer ")
		if err != nil || len(authHeader) <= 1 {
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
			log.Println(err)
			w.WriteHeader(401)
		} else {

			v := reflect.ValueOf(token.Claims)
			i := v.Interface()
			a := i.(jwt.MapClaims)

			for h, m := range a {
				r.Header.Set("X-Croove-Session-"+h, fmt.Sprintf("%v", m))
			}

			handler.ServeHTTP(w, r)
		}
	})
}

// NewReverser creates a new reverser type
func NewReverser(host string, port string) *Reverser {
	rpURL, err := url.Parse(host + port)
	if err != nil {
		log.Fatal(err)
	}

	// initialize our reverse proxy
	reverseProxy := httputil.NewSingleHostReverseProxy(rpURL)
	// wrap that proxy with our sameHostSameHeaders function
	singleHosted := validateJWT(sameHostSameHeaders(reverseProxy))

	rev := Reverser{reverseProxy, singleHosted}
	return &rev
}

// Reverser Is a JWT reverse proxy
type Reverser struct {
	Proxy *httputil.ReverseProxy
	Host  http.Handler
}

// Initiate
func main() {
	// parse ports from cmdline
	for _, a := range os.Args[1 : len(os.Args)-1] {
		ports := strings.Split(a, ":")
		log.Println("ports:", ports)
		rev := NewReverser("http://0.0.0.0:", ports[1])
		go http.ListenAndServe(":"+ports[0], rev.Host)
	}

	a := os.Args[len(os.Args)-1]
	ports := strings.Split(a, ":")
	log.Println("ports:", ports)
	rev := NewReverser("http://0.0.0.0:", ports[1])
	http.ListenAndServe(":"+ports[0], rev.Host)
}
