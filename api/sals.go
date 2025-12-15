package api

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jjeffcaii/mongo-proxy/protocol"
	"github.com/jjeffcaii/mongo-proxy/tools"
	"golang.org/x/crypto/pbkdf2"
)

type ScramConversation interface {
	FirstMessage() (protocol.Document, error)
	Next(challenge []byte) ([]byte, error)
}

type ScramSHA1Conversation struct {
	username string
	password string

	clientNonce string
	serverNonce string
	salt        []byte
	iter        int

	authMessage string
	step        int

	// 新增字段
	serverKey []byte
}

func NewScramSHA1Conversation(user, pass string) *ScramSHA1Conversation {
	return &ScramSHA1Conversation{
		username: user,
		password: pass,
	}
}

func (c *ScramSHA1Conversation) FirstMessage() (protocol.Document, error) {
	c.clientNonce = randomNonce()

	payload := fmt.Sprintf(
		"n,,n=%s,r=%s",
		saslEscape(c.username),
		c.clientNonce,
	)

	c.step = 1

	return protocol.Document{
		{"saslStart", 1},
		{"mechanism", "SCRAM-SHA-1"},
		{"payload", []byte(payload)},
		{"autoAuthorize", 1},
	}, nil
}

func (c *ScramSHA1Conversation) Next(challenge []byte) ([]byte, error) {
	// [新增] 处理 Step 2: 服务端发送最终签名 (v=...)
	if c.step == 2 {
		attrs := parseScramAttrs(challenge)
		serverSignatureBase64 := attrs["v"]

		if serverSignatureBase64 == "" {
			return nil, errors.New("server finished without signature")
		}

		serverSignature, err := base64.StdEncoding.DecodeString(serverSignatureBase64)
		if err != nil {
			return nil, err
		}

		// 验证服务端签名 (ServerSignature = HMAC(ServerKey, AuthMessage))
		expectedSignature := hmacSHA1(c.serverKey, []byte(c.authMessage))

		if !hmac.Equal(serverSignature, expectedSignature) {
			return nil, errors.New("server signature verification failed")
		}

		// 验证通过，状态设为完成
		c.step = 3
		// 返回空字节，表示我们没有更多话要说了，但需要回应一次以完成握手
		return []byte{}, nil
	}

	if c.step != 1 {
		return nil, errors.New("invalid SCRAM state")
	}

	attrs := parseScramAttrs(challenge)

	c.serverNonce = attrs["r"]
	c.salt, _ = base64.StdEncoding.DecodeString(attrs["s"])
	c.iter, _ = strconv.Atoi(attrs["i"])

	clientFirstBare := fmt.Sprintf(
		"n=%s,r=%s",
		saslEscape(c.username),
		c.clientNonce,
	)

	c.authMessage = clientFirstBare + "," + string(challenge)

	finalPayload, err := c.clientFinal()
	if err != nil {
		return nil, err
	}

	c.step = 2
	return finalPayload, nil
}
func (c *ScramSHA1Conversation) clientFinal() ([]byte, error) {
	channel := "biws"
	nonce := c.serverNonce

	withoutProof := fmt.Sprintf("c=%s,r=%s", channel, nonce)
	c.authMessage += "," + withoutProof

	// --- 之前修改过的 MD5 逻辑保持不变 ---
	digest := md5.Sum([]byte(c.username + ":mongo:" + c.password))
	mongoPassword := hex.EncodeToString(digest[:])

	saltedPassword := pbkdf2.Key(
		[]byte(mongoPassword),
		c.salt,
		c.iter,
		20,
		sha1.New,
	)
	// ----------------------------------

	clientKey := hmacSHA1(saltedPassword, []byte("Client Key"))
	storedKey := sha1.Sum(clientKey)
	clientSignature := hmacSHA1(storedKey[:], []byte(c.authMessage))
	clientProof := xorBytes(clientKey, clientSignature)

	// [新增] 计算并保存 ServerKey
	c.serverKey = hmacSHA1(saltedPassword, []byte("Server Key"))

	return []byte(fmt.Sprintf(
		"%s,p=%s",
		withoutProof,
		base64.StdEncoding.EncodeToString(clientProof),
	)), nil
}

type ScramSHA256Conversation struct {
	username string
	password string

	clientNonce string
	serverNonce string
	salt        []byte
	iter        int

	authMessage string
	step        int
}

func NewScramSHA256Conversation(user, pass string) *ScramSHA256Conversation {
	return &ScramSHA256Conversation{
		username: user,
		password: pass,
	}
}

func (c *ScramSHA256Conversation) FirstMessage() (protocol.Document, error) {
	c.clientNonce = randomNonce()

	payload := fmt.Sprintf(
		"n,,n=%s,r=%s",
		saslEscape(c.username),
		c.clientNonce,
	)

	c.step = 1

	return protocol.Document{
		{"saslStart", 1},
		{"mechanism", "SCRAM-SHA-256"},
		{"payload", []byte(payload)},
		{"autoAuthorize", 1},
	}, nil
}

func (c *ScramSHA256Conversation) Next(challenge []byte) ([]byte, error) {
	if c.step != 1 {
		return nil, errors.New("invalid SCRAM state")
	}

	attrs := parseScramAttrs(challenge)

	c.serverNonce = attrs["r"]
	c.salt, _ = base64.StdEncoding.DecodeString(attrs["s"])
	c.iter, _ = strconv.Atoi(attrs["i"])

	clientFirstBare := fmt.Sprintf(
		"n=%s,r=%s",
		saslEscape(c.username),
		c.clientNonce,
	)

	c.authMessage = clientFirstBare + "," + string(challenge)

	channel := "biws"
	nonce := c.serverNonce
	withoutProof := fmt.Sprintf("c=%s,r=%s", channel, nonce)
	c.authMessage += "," + withoutProof

	saltedPassword := pbkdf2.Key(
		[]byte(c.password),
		c.salt,
		c.iter,
		32, // SHA-256 输出 32 bytes
		sha256.New,
	)

	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientSignature := hmacSHA256(storedKey[:], []byte(c.authMessage))
	clientProof := xorBytes(clientKey, clientSignature)

	c.step = 2

	return []byte(fmt.Sprintf(
		"%s,p=%s",
		withoutProof,
		base64.StdEncoding.EncodeToString(clientProof),
	)), nil
}

func parseSaslReply(reply *protocol.OpReply) (
	conversationID int32,
	payload []byte,
	done bool,
	err error,
) {
	doc := reply.Documents[0] // BSON document

	// ok
	ok := tools.LookupFloat64(doc, "ok")
	if ok != 1 {
		return 0, nil, false, errors.New("sasl authentication failed")
	}

	conversationID = tools.LookupInt32(doc, "conversationId")
	payload = tools.LookupBinary(doc, "payload")
	done = tools.LookupBool(doc, "done")

	if payload == nil {
		return 0, nil, false, errors.New("sasl reply missing payload")
	}

	return
}

func Sasl(ctx Context, username, password string) error {

	// 1. isMaster
	_, err := runIsMaster(ctx)
	if err != nil {
		return err
	}

	//mechs := parseSaslMechs(doc, username)
	//mech := chooseScramMechanism(mechs)
	//if mech == "" {
	//	return errors.New("no supported SCRAM mechanism")
	//}
	mech := "SCRAM-SHA-1"
	var conv ScramConversation
	switch mech {
	case "SCRAM-SHA-256":
		conv = NewScramSHA256Conversation(username, password)
	case "SCRAM-SHA-1":
		conv = NewScramSHA1Conversation(username, password)
	default:
		return fmt.Errorf("unsupported mechanism: %s", mech)
	}

	// ---- 2. saslStart ----
	startDoc, err := conv.FirstMessage()
	startQuery := protocol.NewOpQuery()
	startQuery.FullCollectionName = "admin.$cmd"
	startQuery.NumberToReturn = -1
	startQuery.Query = startDoc
	startQuery.Op = &protocol.Op{
		OpHeader: &protocol.Header{
			OpCode:    protocol.OpCodeQuery,
			RequestID: 0,
		},
	}
	tools.PrintOpQuery(startQuery)

	if err := ctx.SendMessage(startQuery); err != nil {
		return err
	}

	// 等待 Reply
	msg, ok := <-ctx.Next()
	if !ok {
		return fmt.Errorf("connection closed during saslStart")
	}

	reply, ok := msg.(*protocol.OpReply)
	if !ok {
		return fmt.Errorf("unexpected reply type: %T", msg)
	}
	tools.PrintOpReply(reply)

	conversationID, payload, done, err := parseSaslReply(reply)
	if err != nil {
		return err
	}

	RequestID := reply.Header().RequestID

	// ---- 3. saslContinue 循环 ----
	for !done {
		nextPayload, err := conv.Next(payload)
		if err != nil {
			return err
		}

		continueDoc := protocol.Document{
			{Key: "saslContinue", Val: int32(1)},
			{Key: "conversationId", Val: conversationID},
			{Key: "payload", Val: nextPayload},
			{Key: "autoAuthorize", Val: int32(1)}, // 添加此行
		}

		continueQuery := protocol.NewOpQuery()
		continueQuery.FullCollectionName = "admin.$cmd"
		continueQuery.NumberToReturn = -1
		continueQuery.Query = continueDoc

		continueQuery.Op = &protocol.Op{
			OpHeader: &protocol.Header{
				OpCode:    protocol.OpCodeQuery,
				RequestID: RequestID + 1,
			},
		}
		RequestID++
		tools.PrintOpQuery(continueQuery)

		if err := ctx.SendMessage(continueQuery); err != nil {
			return err
		}

		msg, ok := <-ctx.Next()
		if !ok {
			return fmt.Errorf("connection closed during saslContinue")
		}

		reply, ok = msg.(*protocol.OpReply)
		if !ok {
			return fmt.Errorf("unexpected reply type: %T", msg)
		}
		tools.PrintOpReply(reply)
		conversationID, payload, done, err = parseSaslReply(reply)
		if err != nil {
			return err
		}
	}

	return nil
}

func hmacSHA1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func randomNonce() string {
	b := make([]byte, 18)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func saslEscape(s string) string {
	s = strings.ReplaceAll(s, "=", "=3D")
	s = strings.ReplaceAll(s, ",", "=2C")
	return s
}

func parseScramAttrs(b []byte) map[string]string {
	m := make(map[string]string)
	for _, part := range strings.Split(string(b), ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}

func runIsMaster(ctx Context) (protocol.Document, error) {
	query := protocol.NewOpQuery()
	query.FullCollectionName = "admin.$cmd"
	query.NumberToReturn = -1
	query.Query = protocol.Document{
		{Key: "isMaster", Val: int32(1)},
	}
	query.Op = &protocol.Op{
		OpHeader: &protocol.Header{
			OpCode:    protocol.OpCodeQuery,
			RequestID: 0,
		},
	}

	if err := ctx.SendMessage(query); err != nil {
		return nil, err
	}

	msg, ok := <-ctx.Next()
	if !ok {
		return nil, errors.New("connection closed during isMaster")
	}

	reply, ok := msg.(*protocol.OpReply)
	if !ok {
		return nil, fmt.Errorf("unexpected reply type: %T", msg)
	}
	tools.PrintOpReply(reply)

	if len(reply.Documents) == 0 {
		return nil, errors.New("isMaster reply has no document")
	}

	return reply.Documents[0], nil
}

func parseSaslMechs(doc protocol.Document, user string) []string {
	arr := tools.LookupArray(doc, "saslSupportedMechs")
	if arr == nil {
		return nil
	}

	var mechs []string
	for _, v := range arr {
		if s, ok := v.(string); ok {
			// 格式: "db.user MECH"
			parts := strings.Split(s, " ")
			if len(parts) == 2 {
				mechs = append(mechs, parts[1])
			}
		}
	}
	return mechs
}

func chooseScramMechanism(mechs []string) string {
	for _, m := range mechs {
		if m == "SCRAM-SHA-256" {
			return "SCRAM-SHA-256"
		}
	}
	for _, m := range mechs {
		if m == "SCRAM-SHA-1" {
			return "SCRAM-SHA-1"
		}
	}
	return ""
}
