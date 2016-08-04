package main

import "testing"

var testconfig1 = []byte(`
{
  "connect": {
    "from": "0.0.0.0:5000",
    "to": "127.0.0.1:8080"
  },
  "routes": [
    {
      "route": "/cars/*path",
      "allow": {
        "method": ["POST", "PUT", "DELETE"],
        "claims": [
          {"key": "role", "value": ["customer", "admin", "support"]},
          {"key": "foo", "value": ["bar"]}
        ]
      }
    },
{
      "route": "/cars/*path",
      "allow": {
        "method": ["GET"],
        "open": true,
        "claims": []
      }
    },
    {
      "route": "/config/*configs",
      "allow": {
        "method": ["GET"],
        "open": true,
        "claims": [
          {"key": "role", "value": ["customer", "admin", "support"]}
        ]
      }
    },
    {
      "route": "/config/*configs",
      "allow": {
        "method": ["PUT"],
        "claims": [
          {"key": "role", "value": ["customer", "admin", "support"]},
          {"key": "foo", "value": ["bar"]}
        ]
      }
    }
  ]
}
`)

var testconfig2 = []byte(`
{
  "connect": {
    "from": "0.0.0.0:5001",
    "to": "127.0.0.1:8081"
  },
  "routes": [
		{
      "route": "/images",
      "allow": {
        "method": ["GET"],
        "open": true,
        "claims": []
      }
    }
  ]
}
`)

func TestConfigParsing(t *testing.T) {
	jwtConfig := ParseConfig([][]byte{testconfig1, testconfig2})
	if len(jwtConfig.Proxies) != 2 {
		t.Errorf("Proxies loaded wrongly! Size 2 is not %v\n", len(jwtConfig.Proxies))
	}
	if jwtConfig.Proxies[1].Routes[0].Route != "/images" {
		t.Errorf("%+v\n", jwtConfig.Proxies[1])
	}
}
