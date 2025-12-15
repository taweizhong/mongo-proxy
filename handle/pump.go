package handle

import (
	"io"
	"log"

	"github.com/jjeffcaii/mongo-proxy/api"
	"github.com/jjeffcaii/mongo-proxy/protocol"
	"github.com/jjeffcaii/mongo-proxy/tools"
)

// Forward 直接转发
func Forward(source api.Context, target api.Context) {
	ch1, ch2 := source.Next(), target.Next()
	for {
		var err error
		select {
		case msg := <-ch1:
			if msg == nil {
				err = io.EOF
				break
			}
			err = target.SendMessage(msg)
			break
		case msg := <-ch2:
			if msg == nil {
				err = io.EOF
				break
			}
			old := msg.Header().RequestID
			msg.Header().RequestID = 0
			var bs []byte
			bs, err = msg.Encode()
			msg.Header().RequestID = old
			if err == nil {
				err = source.Send(bs)
			}
			break
		}
		if err != nil {
			break
		}
	}
}

// ForwardFind 处理find
func ForwardFind(source api.Context, primaryCtx api.Context, fallbackCtx api.Context) {
	chClient := source.Next()        // client -> proxy
	chPrimary := primaryCtx.Next()   // proxy -> primary DB
	chFallback := fallbackCtx.Next() // proxy -> fallback DB

	// 存储最近一次的 find 请求
	var lastFindQuery *protocol.OpQuery
	// 监听msg
	for {
		select {
		// 获取 client msg，转发到primaryDB
		case msg := <-chClient:
			if msg == nil {
				return
			}
			// 解析为OpQuery
			//if query, ok := msg.(*protocol.OpQuery); ok {
			//	// 打印query
			//	tools.PrintOpQuery(query)
			//}
			// 捕获 find 请求
			if q, ok := msg.(*protocol.OpQuery); ok {
				if isFindQuery(q) {
					// 保存最后一个 find 查询
					lastFindQuery = q
				}
			}
			// 所有请求都先转发到 primary
			err := primaryCtx.SendMessage(msg)
			if err != nil {
				return
			}
		// 获取primaryDB msg，转发到fallbackDB（查询为空时）
		case msg := <-chPrimary:
			if msg == nil {
				return
			}
			// 解析 OP_REPLY
			if reply, ok := msg.(*protocol.OpReply); ok {
				//tools.PrintOpReply(reply)
				//判断是否 find 且结果为空
				if IsFindResultEmpty(reply) {
					log.Println("[proxy] primary DB no result → try fallback")
					if lastFindQuery == nil {
						log.Println("[error] lastFindQuery == nil，无法 fallback")
						continue
					}
					//// 请求 ID
					//oldReqID := reply.Header().RequestID
					//// 替换 RequestID，使 fallback 能返回同 ID
					//lastFindQuery.Header().RequestID = oldReqID

					// 转发 find 请求到 fallbackDB
					if err := fallbackCtx.SendMessage(lastFindQuery); err != nil {
						log.Println("[fallback send error]", err)
						continue
					}
					continue
				}
			}

			// primary 有结果 → 原样返回给客户端
			if bs, err := msg.Encode(); err == nil {
				err = source.Send(bs)
				if err != nil {
					log.Println("[proxy send error]", err)
					return // 如果发送失败，终止连接
				}
			}
			continue
		// 获取fallbackDB msg，返回给客户端
		case msg := <-chFallback:
			if msg == nil {
				return
			}
			bs, _ := msg.Encode()
			source.Send(bs)
		}
	}
}

func isFindQuery(q *protocol.OpQuery) bool {
	for _, p := range q.Query {
		if p.Key == "find" {
			return true
		}
	}
	return false
}

// IsFindResultEmpty 判断 OpReply 是否是 find 查询且没有数据
func IsFindResultEmpty(reply *protocol.OpReply) bool {
	if reply == nil || len(reply.Documents) == 0 {
		return false
	}

	doc := reply.Documents[0]

	// 获取 cursor
	cursorVal := tools.LookupDocument(doc, "cursor")
	if cursorVal == nil {
		return false
	}

	// 获取 firstBatch
	firstBatch := tools.LookupArray(cursorVal, "firstBatch")
	if firstBatch == nil {
		return false
	}

	// 获取 cursor id
	idVal := tools.LookupInt64(cursorVal, "id")

	// 获取 ok
	okVal := tools.LookupFloat64(doc, "ok")

	// 条件：firstBatch 为空，cursor id=0，ok=1
	if len(firstBatch) == 0 && idVal == 0 && okVal == 1 {
		return true
	}

	return false
}
