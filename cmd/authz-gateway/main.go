// Command authz-gateway 在本地启动授权判定与凭证生命周期管理服务，
// 并装配演示数据，便于直接验证签发/判定/续期/撤销/轮换全流程。
//
// 启动（默认监听 127.0.0.1:8088）：
//
//	go run ./cmd/authz-gateway
//
// 快速验证见 README.md“验证方法”小节。
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/highcumontoa/authz-gateway-go/internal/config"
	"github.com/highcumontoa/authz-gateway-go/internal/gateway"
	"github.com/highcumontoa/authz-gateway-go/internal/httpserver"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8088", "listen address")
	ttl := flag.Duration("token-ttl", time.Hour, "credential lifetime")
	renewWindow := flag.Duration("renew-window", 30*time.Minute,
		"window before expiry during which renewal is allowed (0 = any time)")
	evidenceSeed := flag.String("evidence-seed", "",
		"32-byte hex/base64raw seed for the audit evidence Ed25519 signing key "+
			"(empty = ephemeral random key per start)")
	flag.Parse()

	cfg := config.Defaults()
	cfg.TokenTTL = *ttl
	cfg.RenewWindow = *renewWindow
	if *evidenceSeed != "" {
		seed, err := decodeKeySeed(*evidenceSeed)
		if err != nil {
			log.Fatalf("evidence-seed: %v", err)
		}
		cfg.AuditEvidenceKeySeed = seed
	}
	gw := gateway.New(cfg)
	if err := seed(gw); err != nil {
		log.Fatalf("seed: %v", err)
	}

	srv := httpserver.New(gw)
	log.Printf("authz-gateway listening on http://%s (ttl=%s renew-window=%s)",
		*addr, cfg.TokenTTL, cfg.RenewWindow)
	if keyInfo, err := gw.EvidencePublicKey(); err == nil {
		log.Printf("audit evidence signing key_id=%s (Ed25519); distribute this to verifiers",
			keyInfo.KeyID)
	}
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// decodeKeySeed 接受 32 字节的 hex（64 字符）或 base64 编码种子。
func decodeKeySeed(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("seed must decode to 32 bytes (hex 64 chars or base64)")
}
