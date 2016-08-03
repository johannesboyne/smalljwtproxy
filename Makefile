all: install

install:
	go get github.com/dgrijalva/jwt-go
	go get github.com/dgrijalva/jwt-go/request
	go get github.com/julienschmidt/httprouter
	go build jwtproxy.go

start:
	./jwtproxy
