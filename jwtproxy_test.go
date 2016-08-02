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
		log.Println("ERRO:", err)
	}

	// Test server that always responds with 200 code, and specific payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, sampleResponse)
	}))
	defer server.Close()

	rev := NewReverser(server.URL, "")
	reverser := httptest.NewServer(rev.Host)
	defer reverser.Close()

	client := &http.Client{}
	log.Println("REVERSER URL", reverser.URL)
	req, err := http.NewRequest("GET", reverser.URL, nil)

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
