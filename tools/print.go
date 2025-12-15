package tools

import (
	"fmt"
	"reflect"

	"github.com/jjeffcaii/mongo-proxy/protocol"
	"github.com/sbunce/bson"
)

var index = 0

// PrintOpReply 打印 OpReply 的详细内容
func PrintOpReply(reply *protocol.OpReply) {
	index = index + 1
	fmt.Printf("======================%d========================\n", index)
	fmt.Printf("OpReply: RequestID=%d, ResponseFlags=%d, CursorID=%d, StartingFrom=%d, NumberReturned=%d\n",
		reply.Header().RequestID,
		reply.ResponseFlags,
		reply.CursorID,
		reply.StartingFrom,
		reply.NumberReturned,
	)
	fmt.Println("Documents:")

	for i, doc := range reply.Documents {
		fmt.Printf("  Document[%d]:\n", i)
		printDocument(doc, "    ")
	}
	fmt.Println("==============================================")
}

// printDocument 打印 bson.Slice 或 bson.Map 文档，递归处理嵌套结构
func printDocument(doc bson.Slice, indent string) {
	for _, pair := range doc {
		switch v := pair.Val.(type) {
		case bson.Slice: // 嵌套文档
			fmt.Printf("%s%s: {\n", indent, pair.Key)
			printDocument(v, indent+"  ")
			fmt.Printf("%s}\n", indent)
		case []interface{}: // bson Array
			fmt.Printf("%s%s: [\n", indent, pair.Key)
			for j, item := range v {
				fmt.Printf("%s  [%d]: %v (%s)\n", indent, j, item, reflect.TypeOf(item))
			}
			fmt.Printf("%s]\n", indent)
		default:
			fmt.Printf("%s%s: %v (%s)\n", indent, pair.Key, pair.Val, reflect.TypeOf(pair.Val))
		}
	}
}

// PrintOpQuery 打印 OpQuery 的详细信息
func PrintOpQuery(query *protocol.OpQuery) {
	if query == nil {
		fmt.Println("OpQuery is nil")
		return
	}

	index = index + 1
	fmt.Printf("======================%d========================\n", index)
	fmt.Printf("OpQuery: Flags=%d, FullCollectionName=%s, NumberToSkip=%d, NumberToReturn=%d\n",
		query.Flags,
		query.FullCollectionName,
		query.NumberToSkip,
		query.NumberToReturn,
	)

	fmt.Println("Query Document:")
	printQDocument(query.Query, "  ")

	if len(query.ReturnFieldsSelector) > 0 {
		fmt.Println("ReturnFieldsSelector Document:")
		printDocument(query.ReturnFieldsSelector, "  ")
	} else {
		fmt.Println("ReturnFieldsSelector: <empty>")
	}

	fmt.Println("==============================================")
}

// printDocument 递归打印 Document
func printQDocument(doc protocol.Document, indent string) {
	for _, pair := range doc {
		switch v := pair.Val.(type) {
		case protocol.Document:
			fmt.Printf("%s%s: {\n", indent, pair.Key)
			printDocument(v, indent+"  ")
			fmt.Printf("%s}\n", indent)
		case []protocol.Document:
			fmt.Printf("%s%s: [\n", indent, pair.Key)
			for _, d := range v {
				fmt.Printf("%s  {\n", indent)
				printDocument(d, indent+"    ")
				fmt.Printf("%s  }\n", indent)
			}
			fmt.Printf("%s]\n", indent)
		case []interface{}:
			fmt.Printf("%s%s: [", indent, pair.Key)
			for i, elem := range v {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Print(formatValue(elem))
			}
			fmt.Println("]")
		default:
			fmt.Printf("%s%s: %v (%s)\n", indent, pair.Key, v, reflect.TypeOf(v).Name())
		}
	}
}

// formatValue 格式化任意值
func formatValue(v interface{}) string {
	switch x := v.(type) {
	case protocol.Document:
		s := "{"
		for i, p := range x {
			if i > 0 {
				s += ", "
			}
			s += fmt.Sprintf("%s: %v", p.Key, p.Val)
		}
		s += "}"
		return s
	default:
		return fmt.Sprintf("%v", v)
	}
}
