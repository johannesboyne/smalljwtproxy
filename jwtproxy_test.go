package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleResponse = `valid return value`

func TestJWTServer(t *testing.T) {
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
	req, err := http.NewRequest("GET", reverser.URL, nil)
	// ...
	req.Header.Add("Authorization", `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0Njg2MDI0MzN9.JWtUiPV-5ATLYq0s-cig1TuzMXumSnJaikWid12cXs0`)
	req.Header.Add("If-None-Match", `W/"wyzzy"`)
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	returnbody, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	if strings.Trim(string(returnbody), "\n") != sampleResponse {
		log.Println(sampleResponse)
		t.Errorf("Wrong return value")
	}
}
