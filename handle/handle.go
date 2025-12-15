package handle

import (
	"log"

	"github.com/jjeffcaii/mongo-proxy/api"
)

func ProxyHandle(ctx api.Context) {
	primaryDB := api.NewBackend("127.0.0.1:27017")
	fallbackDB := api.NewBackend("127.0.0.1:27018")

	primaryCtx, err := primaryDB.NewConn()
	fallbackCtx, err := fallbackDB.NewConn()
	err = api.Sasl(fallbackCtx, "admin", "secret")
	if err != nil {
		log.Println(err)
	}
	ForwardFind(ctx, primaryCtx, fallbackCtx)
}
