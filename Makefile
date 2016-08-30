all: build

installdependencies:
	go get github.com/dgrijalva/jwt-go
	go get github.com/dgrijalva/jwt-go/request
	go get github.com/julienschmidt/httprouter
	go get github.com/chakrit/go-bunyan

build: installdependencies
	go build -o croove-jwt-acl-proxy

linuxbuild: installdependencies
	GOOS=linux GOARCH=amd64 go build -o croove-jwt-acl-proxy-linux

dockerbuild: installdependencies
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o croove-jwt-acl-proxy-docker .

start:
	./croove-jwt-acl-proxy
