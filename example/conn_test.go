package test

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/jjeffcaii/mongo-proxy/tools"
	"golang.org/x/crypto/pbkdf2"

	"github.com/jjeffcaii/mongo-proxy/api"
	"github.com/jjeffcaii/mongo-proxy/protocol"
	"github.com/sbunce/bson"
)

// ===== PBKDF2 (HMAC-SHA1)  =====
func pbkdf2Sha1(password, salt []byte, iter int) []byte {
	// U1 = HMAC(P, salt + INT(1))
	h := hmac.New(sha1.New, password)
	h.Write(append(salt, 0, 0, 0, 1))
	u := h.Sum(nil)

	result := make([]byte, len(u))
	copy(result, u)

	// U2..Ui
	for i := 1; i < iter; i++ {
		h = hmac.New(sha1.New, password)
		h.Write(u)
		u = h.Sum(nil)
		for j := range u {
			result[j] ^= u[j]
		}
	}
	return result
}

func hmacSha1(key, msg []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func sha1Hash(b []byte) []byte {
	h := sha1.New()
	h.Write(b)
	return h.Sum(nil)
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// ====== TEST =======
func Test_DirectFindAdminUsers(t *testing.T) {
	username := "admin"
	password := "secret"
	db := "admin"

	fallback := api.NewBackend("127.0.0.1:27018")
	c, err := fallback.NewConn()
	if err != nil {
		t.Fatalf("connect backend error: %v", err)
	}
	defer c.Close()

	// ====== 1. saslStart ======

	// 生成随机 nonce
	nonceBytes := make([]byte, 18)
	rand.Read(nonceBytes)
	clientNonce := base64.StdEncoding.EncodeToString(nonceBytes)

	clientFirstMessageBare := fmt.Sprintf("n=%s,r=%s", username, clientNonce)
	clientFirstMessage := "n,," + clientFirstMessageBare

	q1 := &protocol.OpQuery{
		Op: &protocol.Op{
			OpHeader: &protocol.Header{
				OpCode:    protocol.OpCodeQuery,
				RequestID: 1,
			},
		},
		FullCollectionName: "admin.$cmd",
		NumberToReturn:     -1,
		Query: bson.Slice{
			{Key: "saslStart", Val: int32(1)},
			{Key: "mechanism", Val: "SCRAM-SHA-1"}, // ⭐ 修改为 SCRAM-SHA-1
			{Key: "payload", Val: base64.StdEncoding.EncodeToString([]byte(clientFirstMessage))},
			{Key: "$db", Val: db},
		},
	}

	if err := c.SendMessage(q1); err != nil {
		t.Fatalf("send saslStart error: %v", err)
	}

	r1 := <-c.Next()
	reply1 := r1.(*protocol.OpReply)
	doc1 := reply1.Documents[0]

	payload1, _ := protocol.Load(doc1, "payload")
	serverFirstBase64 := payload1.(bson.String)
	serverFirstRaw, _ := base64.StdEncoding.DecodeString(string(serverFirstBase64))
	serverFirst := string(serverFirstRaw)

	// 解析 serverFirstMessage: r=...,s=...,i=...
	var serverNonce, salt string
	var iter int
	fmt.Sscanf(serverFirst, "r=%[^,],s=%[^,],i=%d", &serverNonce, &salt, &iter)

	saltBytes, _ := base64.StdEncoding.DecodeString(salt)

	// ====== 派生 SCRAM-SHA-1 saltedPassword ======
	saltedPassword := pbkdf2.Key([]byte(password), saltBytes, iter, 20, sha1.New)

	clientKey := hmacSha1(saltedPassword, []byte("Client Key"))
	storedKey := sha1Hash(clientKey)

	clientFinalMessageWithoutProof := fmt.Sprintf("c=biws,r=%s", serverNonce)
	authMsg := clientFirstMessageBare + "," + serverFirst + "," + clientFinalMessageWithoutProof

	clientSignature := hmacSha1(storedKey, []byte(authMsg))
	clientProof := xorBytes(clientKey, clientSignature)
	clientProofBase64 := base64.StdEncoding.EncodeToString(clientProof)

	clientFinalMessage := fmt.Sprintf("%s,p=%s", clientFinalMessageWithoutProof, clientProofBase64)

	// ====== 2. saslContinue ======
	convID, _ := protocol.Load(doc1, "conversationId")
	conversationId := int(convID.(bson.Int32))

	q2 := &protocol.OpQuery{
		Op: &protocol.Op{
			OpHeader: &protocol.Header{
				OpCode:    protocol.OpCodeQuery,
				RequestID: 2,
			},
		},
		FullCollectionName: "admin.$cmd",
		NumberToReturn:     -1,
		Query: bson.Slice{
			{Key: "saslContinue", Val: int32(1)},
			{Key: "conversationId", Val: conversationId},
			{Key: "payload", Val: base64.StdEncoding.EncodeToString([]byte(clientFinalMessage))},
			{Key: "$db", Val: db},
		},
	}

	if err := c.SendMessage(q2); err != nil {
		t.Fatalf("send saslContinue error: %v", err)
	}

	r2 := <-c.Next()
	reply2 := r2.(*protocol.OpReply)
	doc2 := reply2.Documents[0]

	// ====== 3. saslContinue2 ======
	convID, _ = protocol.Load(doc2, "conversationId")
	conversationId = int(convID.(bson.Int32))

	q3 := &protocol.OpQuery{
		Op: &protocol.Op{
			OpHeader: &protocol.Header{
				OpCode:    protocol.OpCodeQuery,
				RequestID: 3,
			},
		},
		FullCollectionName: "admin.$cmd",
		NumberToReturn:     -1,
		Query: bson.Slice{
			{Key: "saslContinue", Val: int32(1)},
			{Key: "conversationId", Val: conversationId},
			{Key: "payload", Val: ""},
			{Key: "$db", Val: db},
		},
	}
	if err := c.SendMessage(q3); err != nil {
		t.Fatalf("send saslContinue2 error: %v", err)
	}
	<-c.Next() // server-final OK

	// ====== 4. Auth OK，执行 find ======
	qFind := &protocol.OpQuery{
		FullCollectionName: "admin.$cmd",
		NumberToReturn:     -1,
		Query: bson.Slice{
			{Key: "find", Val: "users"},
			{Key: "filter", Val: ""},
			{Key: "$db", Val: db},
		},
	}

	if err := c.SendMessage(qFind); err != nil {
		t.Fatalf("send find error: %v", err)
	}

	replyMsg := <-c.Next()
	reply := replyMsg.(*protocol.OpReply)

	fmt.Println("Reply:")
	tools.PrintOpReply(reply)
}

func Test_DirectFind(t *testing.T) {

	fallback := api.NewBackend("127.0.0.1:27018")
	ctx, err := fallback.NewConn()
	if err != nil {
		t.Fatalf("connect backend error: %v", err)
	}
	defer ctx.Close()
	qFind := &protocol.OpQuery{
		Op: &protocol.Op{
			OpHeader: &protocol.Header{
				OpCode:    protocol.OpCodeQuery,
				RequestID: 123,
			},
		},
		FullCollectionName: "admin.$cmd",
		NumberToReturn:     -1,
		Query: bson.Slice{
			{Key: "find", Val: "users"},
			{Key: "filter", Val: bson.BSON{}},
			{Key: "$db", Val: "amdin"},
		},
	}

	if err := ctx.SendMessage(qFind); err != nil {
		t.Fatalf("send find error: %v", err)
	}

	replyMsg := <-ctx.Next()
	reply := replyMsg.(*protocol.OpReply)

	fmt.Println("Reply:")
	tools.PrintOpReply(reply)
}
