// audit-verify 是独立的审计证据核验工具：不依赖任何服务访问权限，
// 仅凭一份导出的证据文件即可给出可区分的核验结论。
//
// 用法：
//
//	audit-verify <evidence.json>   从文件读取
//	audit-verify -                 从标准输入读取
//
// 输出核验结论 JSON；结论为 ok 时退出码 0，否则为 1，参数/读取错误为 2。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: audit-verify <evidence.json|->")
		os.Exit(2)
	}
	var data []byte
	var err error
	if os.Args[1] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "read evidence:", err)
		os.Exit(2)
	}
	v := audit.VerifyEvidence(data)
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
	if v.Verdict != audit.VerdictOK {
		os.Exit(1)
	}
}
