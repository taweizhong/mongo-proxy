package test

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/jjeffcaii/mongo-proxy/api"
	"github.com/jjeffcaii/mongo-proxy/protocol"
	"github.com/jjeffcaii/mongo-proxy/tools"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Test_Conn(t *testing.T) {
	// 设置连接超时
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// MongoDB URI
	uri := "mongodb://admin:secret@127.0.0.1:27018/admin"

	clientOptions := options.Client().ApplyURI(uri)

	// 连接 MongoDB
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Ping 数据库
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Cannot connect to MongoDB:", err)
	}

	fmt.Println("Connected to MongoDB 3.4 successfully!")

	// 指定数据库和集合
	collection := client.Database("admin").Collection("users")

	// 插入数据
	doc := map[string]interface{}{
		"name": "test",
		"age":  21,
	}
	for i := 0; i < 10; i++ {
		result, err := collection.InsertOne(context.Background(), doc)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Inserted ID:", result.InsertedID)
	}
}

func QueryAll(ctx context.Context, coll *mongo.Collection) ([]map[string]interface{}, error) {
	// 空 filter 表示查询全部
	cur, err := coll.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)

	var results []map[string]interface{}
	for cur.Next(ctx) {
		var item map[string]interface{}
		if err := cur.Decode(&item); err != nil {
			return nil, err
		}
		results = append(results, item)
	}

	if err := cur.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

func Test_FindALL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	//uri := "mongodb://admin:Sa287h32H128hE3SSD02e@47.89.18.64:23638/admin?directConnection=true&readPreference=secondaryPreferred"
	//uri := "mongodb://admin:Sa287h32H128hE3SSD02e@127.0.0.1:27019/admin?directConnection=true&readPreference=secondaryPreferred"
	//uri := "mongodb://admin:admin@hkg-test-mgo.everonet.com:23636"
	uri := "mongodb://admin:secret@localhost:27019"
	clientOptions := options.Client().ApplyURI(uri)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Ping
	if err = client.Ping(ctx, nil); err != nil {
		log.Fatal("Cannot connect to MongoDB:", err)
	}

	fmt.Println("Connected to MongoDB 3.4 successfully!")

	//collection := client.Database("settle").Collection("cardbin")
	collection := client.Database("admin").Collection("users")
	// 查询所有文档
	all, err := QueryAll(ctx, collection)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("All documents:")
	for _, v := range all {
		fmt.Println(v)
	}
}

type User struct {
	ID   primitive.ObjectID `bson:"_id"`
	Name string             `bson:"name"`
	Age  int32              `bson:"age"`
}

func Test_FindIF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	//uri := "mongodb://admin:Sa287h32H128hE3SSD02e@47.89.18.64:23638/admin?directConnection=true&readPreference=secondaryPreferred"
	//uri := "mongodb://admin:Sa287h32H128hE3SSD02e@127.0.0.1:27019/admin?directConnection=true&readPreference=secondaryPreferred"
	//uri := "mongodb://admin:admin@hkg-test-mgo.everonet.com:23636"
	uri := "mongodb://admin:secret@localhost:27019"
	clientOptions := options.Client().ApplyURI(uri)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Ping
	if err = client.Ping(ctx, nil); err != nil {
		log.Fatal("Cannot connect to MongoDB:", err)
	}

	fmt.Println("Connected to MongoDB 3.4 successfully!")

	//collection := client.Database("settle").Collection("cardbin")
	collection := client.Database("admin").Collection("users")
	filter := bson.M{"name": "Alice"}
	log.Printf("执行查询: 集合=%s, 过滤条件=%v", "users", filter)

	// 5. 执行 Find 操作
	// Find 返回一个 Cursor（游标），用于迭代结果
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		log.Fatalf("执行 Find 操作失败: %v", err)
	}
	defer cursor.Close(ctx) // 确保游标在函数结束时关闭

	// 6. 迭代游标并处理结果
	var results []User
	fmt.Println("\n--- 查询结果 (name=\"test\") ---")

	// 迭代游标中的所有结果
	for cursor.Next(ctx) {
		var doc User
		// 将当前游标指向的 BSON 文档解码到 Go 结构体中
		if err := cursor.Decode(&doc); err != nil {
			log.Fatalf("解码文档失败: %v", err)
		}
		results = append(results, doc)

		// 打印查询到的单个文档
		fmt.Printf("ID: %v, Name: %s, Value: %v\n", doc.ID, doc.Name, doc.Age)
	}

	// 检查迭代过程中是否有错误发生
	if err := cursor.Err(); err != nil {
		log.Fatalf("游标迭代错误: %v", err)
	}

	// 7. 最终总结
	fmt.Printf("\n总共查询到 %d 个文档。\n", len(results))
}

func Test_Sasl_WithCommand(t *testing.T) {
	backend := api.NewBackend("127.0.0.1:27018")

	ctx, err := backend.NewConn()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()

	if err := api.Sasl(ctx, "admin", "admin"); err != nil {
		t.Fatalf("auth failed: %v", err)
	}

	// ---- 发送一个 command 验证身份 ----
	cmd := protocol.NewOpQuery()
	cmd.FullCollectionName = "admin.$cmd"
	cmd.NumberToReturn = -1
	cmd.Query = protocol.Document{
		{Key: "connectionStatus", Val: int32(1)},
	}

	if err := ctx.SendMessage(cmd); err != nil {
		t.Fatal(err)
	}

	msg := <-ctx.Next()
	reply, ok := msg.(*protocol.OpReply)
	if !ok {
		t.Fatalf("unexpected reply: %T", msg)
	}

	doc := reply.Documents[0]
	authInfo := tools.LookupDocument(doc, "authInfo")
	if authInfo == nil {
		t.Fatal("no authInfo in reply")
	}

	t.Log("authInfo:", authInfo)
}

func Test_Sasl(t *testing.T) {
	backend := api.NewBackend("127.0.0.1:27017")

	ctx, err := backend.NewConn()
	if err != nil {
		t.Fatalf("new conn failed: %v", err)
	}
	defer ctx.Close()

	done := make(chan error, 1)

	// SASL 是同步协议，但 ctx.Next() 在 goroutine 里跑
	go func() {
		err := api.Sasl(ctx, "admin", "secret")
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sasl auth failed: %v", err)
		}
		t.Log("SCRAM-SHA-1 auth success")
	case <-time.After(100 * time.Second):
		t.Fatal("sasl auth timeout")
	}
}
