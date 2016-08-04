package main

import (
	"encoding/json"
	"log"
)

// ParseConfig multiple config strings into a JWT config with multiple
// proxies.
func ParseConfig(configStrings [][]byte) *JWTConfig {

	jwtConfig := &JWTConfig{
		Proxies: []Proxy{},
	}
	for _, config := range configStrings {
		var proxyConfig Proxy
		err := json.Unmarshal(config, &proxyConfig)
		if err != nil {
			log.Fatal(err)
		}

		jwtConfig.Proxies = append(jwtConfig.Proxies, proxyConfig)
	}

	return jwtConfig
}
