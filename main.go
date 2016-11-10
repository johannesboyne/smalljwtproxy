package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/chakrit/go-bunyan"
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

var logger bunyan.Log

// Initiate
func main() {
	var configPath arrayFlags
	var configs [][]byte

	logLevel := flag.String("log", "INFO", "Log Level (DEBUG; INFO; WARN; ERROR)")
	flag.Var(&configPath, "config", "Configuration file")
	flag.Parse()

	// Setup logging
	loggingLevel := bunyan.ParseLevel(*logLevel)
	logger = bunyan.NewStdLogger("JWT-PROXY", bunyan.FilterSink(loggingLevel, bunyan.StdoutSink()))

	// Collect different config files if necessary
	for _, c := range configPath {
		logger.Debugf("[DEBUG] load config: %s\n", c)
		file, err := ioutil.ReadFile(c)
		if err != nil {
			logger.Fatalf("%+v\n", err)
		}
		configs = append(configs, file)
	}

	proxyConfig := ParseConfig(configs)

	if len(proxyConfig.Proxies) >= 1 {
		for _, pc := range proxyConfig.Proxies[1:len(proxyConfig.Proxies)] {
			go func(proxy *Proxy) {
				logger.Debugf("[DEBUG] start proxy...")
				proxy.Collection = make(map[string]AccessControl)

				to := strings.Split(proxy.Connect.To, ":")
				from := strings.Split(proxy.Connect.From, ":")
				rev := NewReverser("http://"+to[0]+":", to[1], proxy)
				logger.Debugf("[DEBUG] %s %v\n", initLog, from[1])
				logger.Fatalf("%+v\n", http.ListenAndServe(":"+from[1], rev.Host))
			}(&pc)
		}
	}

	proxy := proxyConfig.Proxies[0]
	proxy.Collection = make(map[string]AccessControl)

	to := strings.Split(proxy.Connect.To, ":")
	from := strings.Split(proxy.Connect.From, ":")
	rev := NewReverser("http://"+to[0]+":", to[1], &proxy)
	logger.Debugf("[DEBUG] %s %v\n", initLog, from[1])
	logger.Fatalf("%+v\n", http.ListenAndServe(":"+from[1], rev.Host))
}
