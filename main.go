package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/logutils"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprintf("%s", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

const initLog = "initialized and proxy started on:"

// Initiate
func main() {
	var configPath arrayFlags
	var configs [][]byte

	logLevel := flag.String("log", "INFO", "Log Level (DEBUG; INFO; WARN; ERROR)")
	flag.Var(&configPath, "config", "Configuration file")
	flag.Parse()

	// Setup logging
	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN", "ERROR"},
		MinLevel: logutils.LogLevel(*logLevel),
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)

	// Collect different config files if necessary
	for _, c := range configPath {
		log.Printf("[DEBUG] load config: %s\n", c)
		file, err := ioutil.ReadFile(c)
		if err != nil {
			log.Fatal(err)
		}
		configs = append(configs, file)
	}

	proxyConfig := ParseConfig(configs)

	if len(proxyConfig.Proxies) >= 1 {
		for _, pc := range proxyConfig.Proxies[1:len(proxyConfig.Proxies)] {
			go func(proxy Proxy) {
				log.Println("[DEBUG] start proxy...")
				proxy.Collection = make(map[string]AccessControl)

				to := strings.Split(proxy.Connect.To, ":")
				from := strings.Split(proxy.Connect.From, ":")
				rev := NewReverser("http://"+to[0]+":", to[1], proxy)
				log.Printf("[DEBUG] %s %v\n", initLog, from[1])
				log.Fatal(http.ListenAndServe(":"+from[1], rev.Host))
			}(pc)
		}
	}

	proxy := proxyConfig.Proxies[0]
	proxy.Collection = make(map[string]AccessControl)

	to := strings.Split(proxy.Connect.To, ":")
	from := strings.Split(proxy.Connect.From, ":")
	rev := NewReverser("http://"+to[0]+":", to[1], proxy)
	log.Printf("[DEBUG] %s %v\n", initLog, from[1])
	log.Fatal(http.ListenAndServe(":"+from[1], rev.Host))
}
