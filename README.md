JWT (token validator & ACL) PROXY
=================================

A very simpel JWT token validator and ACL proxy.

#Installation on OS X

- Install go: `brew install go`
- GOPATH=$HOME/go make

#Example use

```
JWT_SECRET=<secret> jwtproxy -config=./config.json
```

#Noticeable JWT proxies

- https://github.com/coreos/jwtproxy
- https://github.com/auth0/nginx-jwt

#License

MIT

