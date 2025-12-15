package main

import (
	"log"

	"github.com/jjeffcaii/mongo-proxy/api"
	"github.com/jjeffcaii/mongo-proxy/handle"
)

func main() {
	// 创建代理
	proxy := api.NewProxy(":27019")
	log.Println("proxy server start")
	err := proxy.Serve(handle.ProxyHandle)
	if err != nil {
		return
	}
}
