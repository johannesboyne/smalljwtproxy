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

	for _, pc := range proxyConfig.Proxies[:len(proxyConfig.Proxies)-1] {
		log.Println("MORE THAN 1? Sorry not implemented", pc)
		panic("not implemented")
	}

	proxy := proxyConfig.Proxies[0]
	proxyConfig.Collection = make(map[string]AccessControl)

	to := strings.Split(proxy.Connect.To, ":")
	from := strings.Split(proxy.Connect.From, ":")
	rev := NewReverser("http://"+to[0]+":", to[1], *proxyConfig)
	log.Println("Initialized and proxy started on:", from[1])
	log.Fatal(http.ListenAndServe(":"+from[1], rev.Host))
}
