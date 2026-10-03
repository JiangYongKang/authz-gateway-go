// Command audit-evidence-verify 是审计证据产物的**独立离线核验工具**。
//
// 它只依赖 Go 标准库与 internal/evidence 的核验逻辑，不需要、也不会发起任何
// 服务访问：输入一份导出的 JSON 产物文件（或 - 表示标准输入），输出核验
// 结论，并用进程退出码区分结果。
//
// 用法：
//
//	audit-evidence-verify [-expect-key KEYID] [-expect-from N] [-expect-to M] evidence.json
//
// 退出码：
//
//	0 完整连续、未被改写（valid）
//	2 声明范围不合法（invalid_range）
//	3 缺号（missing_records）
//	4 重排/重复（reordered_or_dup）
//	5 内容被改写（content_tampered）
//	6 链根不一致（root_mismatch）
//	7 签名不通过（bad_evidence_signature）
//	8 产物损坏/无法解析（artifact_malformed）
//	9 不支持的算法或版本（unsupported_key_alg）
//	10 与期望（key/范围）不符
//	1 其它用法错误
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/highcumontoa/authz-gateway-go/internal/evidence"
)

func main() {
	var (
		expectKey  = flag.String("expect-key", "", "expected signing key_id (optional trust anchor)")
		expectFrom = flag.Int64("expect-from", 0, "expected range_from (0 = do not check)")
		expectTo   = flag.Int64("expect-to", 0, "expected range_to (0 = do not check)")
	)
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: audit-evidence-verify [flags] evidence.json|-")
		os.Exit(1)
	}
	raw, err := readInput(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "read evidence: %v\n", err)
		os.Exit(1)
	}

	res := evidence.Verify(raw)

	// 即使签名通过，也可选地把产物绑定到期望的 key_id 与范围：
	// 防止“用另一把合法密钥/另一段合法范围伪造”的产物被当成本次证据。
	if res.OK() {
		var a evidence.Artifact
		if err := json.Unmarshal(raw, &a); err == nil {
			if *expectKey != "" && a.KeyID != *expectKey {
				res.Status = "expectation_mismatch"
				res.Detail = fmt.Sprintf("key_id=%s, want %s", a.KeyID, *expectKey)
			} else if *expectFrom != 0 && a.RangeFrom != *expectFrom {
				res.Status = "expectation_mismatch"
				res.Detail = fmt.Sprintf("range_from=%d, want %d", a.RangeFrom, *expectFrom)
			} else if *expectTo != 0 && a.RangeTo != *expectTo {
				res.Status = "expectation_mismatch"
				res.Detail = fmt.Sprintf("range_to=%d, want %d", a.RangeTo, *expectTo)
			}
		}
	}

	fmt.Printf("status: %s\n", res.Status)
	if res.Detail != "" {
		fmt.Printf("detail: %s\n", res.Detail)
	}
	if res.KeyID != "" {
		fmt.Printf("key_id: %s\n", res.KeyID)
	}
	if res.AtID != 0 || res.WantID != 0 || res.GotID != 0 {
		fmt.Printf("at_id=%d want_id=%d got_id=%d\n", res.AtID, res.WantID, res.GotID)
	}
	os.Exit(exitCode(res.Status))
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return readAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func readAll(f *os.File) ([]byte, error) {
	return io.ReadAll(f)
}

func exitCode(status string) int {
	switch status {
	case evidence.StatusValid:
		return 0
	case evidence.StatusInvalidRange:
		return 2
	case evidence.StatusGap:
		return 3
	case evidence.StatusReordered:
		return 4
	case evidence.StatusTampered:
		return 5
	case evidence.StatusRootMismatch:
		return 6
	case evidence.StatusBadSignature:
		return 7
	case evidence.StatusMalformed:
		return 8
	case evidence.StatusUnsupportedKeyAlg:
		return 9
	default:
		return 10
	}
}
