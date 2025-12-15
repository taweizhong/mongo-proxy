package tools

import (
	"github.com/jjeffcaii/mongo-proxy/protocol"
	"github.com/sbunce/bson"
)

// LookupDocument 从 Document 中查找 key 对应的 Document（bson.Slice）
func LookupDocument(doc protocol.Document, key string) protocol.Document {
	for _, p := range doc {
		if p.Key == key {
			if nested, ok := p.Val.(protocol.Document); ok {
				return nested
			}
		}
	}
	return nil
}

// LookupArray 从 Document 中查找 key 对应的 Array
func LookupArray(doc protocol.Document, key string) []interface{} {
	for _, p := range doc {
		if p.Key == key {
			if arr, ok := p.Val.(bson.Array); ok {
				return arr
			}
		}
	}
	return nil
}

// LookupInt64 查找 int64 类型字段
func LookupInt64(doc protocol.Document, key string) int64 {
	for _, p := range doc {
		if p.Key == key {
			switch v := p.Val.(type) {
			case bson.Int64:
				return int64(v)
			case bson.Int32:
				return int64(v)
			case int64:
				return v
			case int32:
				return int64(v)
			}
		}
	}
	return 0
}

// LookupFloat64 查找 float64 类型字段
func LookupFloat64(doc protocol.Document, key string) float64 {
	for _, p := range doc {
		if p.Key == key {
			switch v := p.Val.(type) {
			case bson.Float:
				return float64(v)
			case float64:
				return v
			case int32:
				return float64(v)
			case int64:
				return float64(v)
			}
		}
	}
	return 0
}

func LookupBool(doc protocol.Document, key string) bool {
	for _, p := range doc {
		if p.Key == key {
			switch v := p.Val.(type) {
			case bool:
				return v
			case bson.Bool:
				return bool(v)
			case int32:
				return v != 0
			case int64:
				return v != 0
			case bson.Int32:
				return int32(v) != 0
			case bson.Int64:
				return int64(v) != 0
			}
		}
	}
	return false
}

func LookupBinary(doc protocol.Document, key string) []byte {
	for _, p := range doc {
		if p.Key == key {
			switch v := p.Val.(type) {
			case bson.Binary:
				return v
			case []byte:
				return v
			}
		}
	}
	return nil
}

func LookupInt32(doc protocol.Document, key string) int32 {
	for _, p := range doc {
		if p.Key == key {
			switch v := p.Val.(type) {
			case bson.Int32:
				return int32(v)
			case bson.Int64:
				return int32(v)
			case int32:
				return v
			case int64:
				return int32(v)
			}
		}
	}
	return 0
}
