package api

import (
	"errors"
	"log"
	"net"
)

// 代理
type proxy struct {
	addr     string
	listener net.Listener
}

// Serve 提供服务
func (p *proxy) Serve(handler func(Context)) error {
	if p.listener != nil {
		return errors.New("listener has been created already")
	}
	// 监听端口
	listen, err := net.Listen("tcp", p.addr)
	if err != nil {
		return err
	}
	defer func(listen net.Listener) {
		err := listen.Close()
		if err != nil {
			log.Println("Error closing listener: ", err)
		}
	}(listen)
	p.listener = listen
	for {
		// 接受
		conn, err := p.listener.Accept()
		if err != nil {
			log.Println("accept connection failed:", err)
			break
		}
		// 处理
		go func() {
			ctx := newContext(conn)
			defer func(ctx Context) {
				err := ctx.Close()
				if err != nil {
					log.Println("Error closing context:", err)
				}
			}(ctx)
			handler(ctx)
		}()
	}
	return nil
}

func (p *proxy) Close() error {
	if p.listener == nil {
		return nil
	}
	if err := p.listener.Close(); err != nil {
		return err
	}
	p.listener = nil
	return nil
}

func NewProxy(addr string) Endpoint {
	return &proxy{addr: addr}
}
