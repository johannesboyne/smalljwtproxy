package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// Initiate
func main() {
	var configPath arrayFlags
	var configs [][]byte

	flag.Var(&configPath, "config", "Configuration file")
	flag.Parse()

	for _, c := range configPath {
		fmt.Printf("config: %s\n", c)

		file, err := ioutil.ReadFile(c)
		if err != nil {
			log.Fatal(err)
		}
		configs = append(configs, file)
	}

	proxyConfig := ParseConfig(configs)

	if len(proxyConfig.Proxies) >= 1 {
		log.Println("legnth >= 1")
		for _, pc := range proxyConfig.Proxies[1:len(proxyConfig.Proxies)] {
			log.Println(1, len(proxyConfig.Proxies)-1)
			go func(proxy Proxy) {
				log.Println("setup")
				proxy.Collection = make(map[string]AccessControl)

				to := strings.Split(proxy.Connect.To, ":")
				from := strings.Split(proxy.Connect.From, ":")
				rev := NewReverser("http://"+to[0]+":", to[1], proxy)
				log.Println("Initialized and proxy started on:", from[1])
				log.Fatal(http.ListenAndServe(":"+from[1], rev.Host))
			}(pc)
		}
	}

	proxy := proxyConfig.Proxies[0]
	proxy.Collection = make(map[string]AccessControl)

	to := strings.Split(proxy.Connect.To, ":")
	from := strings.Split(proxy.Connect.From, ":")
	rev := NewReverser("http://"+to[0]+":", to[1], proxy)
	log.Println("Initialized and proxy started on:", from[1])
	log.Fatal(http.ListenAndServe(":"+from[1], rev.Host))
}
