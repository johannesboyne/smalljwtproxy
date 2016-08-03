package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const sampleResponse = `valid return value`

func TestJWTServer(t *testing.T) {

	os.Setenv("JWT_SECRET", "shhhhh")
	mySigningKey := []byte("shhhhh")

	type MyCustomClaims struct {
		Foo string `json:"foo"`
		jwt.StandardClaims
	}
	now := time.Now().Add(time.Second)
	secs := now.Unix()
	// Create the Claims
	claims := MyCustomClaims{
		"bar",
		jwt.StandardClaims{
			ExpiresAt: secs,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(mySigningKey)

	if err != nil {
		panic(err)
	}

	// Test server that always responds with 200 code, and specific payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, sampleResponse)
	}))
	defer server.Close()

	reverser := httptest.NewUnstartedServer(nil)
	rev := NewReverser(server.URL, "", JWTConfig{
		Proxies: []Proxies{
			{
				Connect: FromTo{
					From: strings.Replace(reverser.URL, "http://", "", -1),
					To:   strings.Replace(server.URL, "http://", "", -1),
				},
				Routes: []AccessControl{
					{
						Route: "/closed",
						Allow: AccessDefinition{
							Method: []string{"GET"},
							Claims: []claim{
								{Key: "foo", Value: []string{"bar"}},
							},
						},
					},
				},
			},
		},
		Collection: make(map[string]AccessControl),
	})
	reverser.Config = &http.Server{Handler: rev.Host}
	reverser.Start()
	defer reverser.Close()

	log.Println("FROM:", reverser.URL)
	log.Println("TO  :", server.URL)
	log.Println("req.:", reverser.URL+"/closed")
	client := &http.Client{}
	req, err := http.NewRequest("GET", reverser.URL+"/closed", nil)

	req.Header.Add("Authorization", `Bearer `+ss)

	res, err := client.Do(req)

	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}
	returnbody, err := ioutil.ReadAll(res.Body)
	res.Body.Close()

	if res.Status != "200 OK" {
		t.Errorf("Status %s\nStatus not 200", res.Status)
	}
	if err != nil {
		t.Errorf(fmt.Sprintf("%v", err))
	}
	if strings.Trim(string(returnbody), "\n") != sampleResponse {
		t.Errorf("Return body mismatches")
	}
}
