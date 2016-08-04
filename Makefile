all: build

build:
	go get github.com/dgrijalva/jwt-go
	go get github.com/dgrijalva/jwt-go/request
	go get github.com/julienschmidt/httprouter
	go build -o croove-jwt-acl-proxy

start:
	./croove-jwt-acl-proxy
