JWT (token validator) PROXY
===========================

A very simpel JWT token validator proxy.

#Example use

```
# JWT_SECRET=<secret> jwtproxy <from>:<to>
JWT_SECRET=youverysecretsecret jwtproxy 5000:3000 5001:3001
```

#Noticeable JWT proxies

- https://github.com/coreos/jwtproxy
- https://github.com/auth0/nginx-jwt

#License

MIT
