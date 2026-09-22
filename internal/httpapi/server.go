// Package httpapi 把授权服务暴露为本地 HTTP 接口。
// 所有业务判定都委托给 service.Service，保证 HTTP 与其他入口结论完全一致。
//
// 安全约定：
//   - 任何错误响应都不携带原始凭证或密钥；访问凭证仅经 Authorization 头传入。
//   - 授权不通过（凭证无效/显式拒绝/默认拒绝）一律返回 403；
//     请求格式错误返回 400；系统失败（含审计写满 fail-closed）返回 503。
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/highcumontoa/authz-gateway-go/internal/audit"
	"github.com/highcumontoa/authz-gateway-go/internal/authz"
	"github.com/highcumontoa/authz-gateway-go/internal/service"
	"github.com/highcumontoa/authz-gateway-go/internal/store"
)

// Server 装配 HTTP 路由。
type Server struct {
	svc *service.Service
	mux *http.ServeMux
}

// New 创建 HTTP 服务并注册路由。
func New(svc *service.Service) *Server {
	s := &Server{svc: svc, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler 返回可挂载的 http.Handler。
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/v1/login", s.handleLogin)
	s.mux.HandleFunc("/v1/refresh", s.handleRefresh)
	s.mux.HandleFunc("/v1/logout", s.handleLogout)
	s.mux.HandleFunc("/v1/authorize", s.handleAuthorize)
	s.mux.HandleFunc("/v1/audit", s.handleAudit)
	s.mux.HandleFunc("/v1/audit/verify", s.handleAuditVerify)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type loginReq struct {
	UserID string `json:"user_id"`
}

type tokensResp struct {
	SessionID    string `json:"session_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccessExp    string `json:"access_exp"`
	RefreshExp   string `json:"refresh_exp"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("method_not_allowed"))
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
		return
	}
	res, err := s.svc.Login(req.UserID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokensResp{
		SessionID: res.SessionID, AccessToken: res.AccessToken, RefreshToken: res.RefreshToken,
		AccessExp:  res.AccessExp.UTC().Format("2006-01-02T15:04:05Z"),
		RefreshExp: res.RefreshExp.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("method_not_allowed"))
		return
	}
	var req refreshReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
		return
	}
	res, err := s.svc.Refresh(req.RefreshToken)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokensResp{
		SessionID: res.SessionID, AccessToken: res.AccessToken, RefreshToken: res.RefreshToken,
		AccessExp:  res.AccessExp.UTC().Format("2006-01-02T15:04:05Z"),
		RefreshExp: res.RefreshExp.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("method_not_allowed"))
		return
	}
	var req refreshReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
		return
	}
	if err := s.svc.RevokeSessionByToken(req.RefreshToken); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

type authorizeReq struct {
	Action     string `json:"action"`
	ResourceID string `json:"resource_id"`
}

type ruleTraceJSON struct {
	PolicyID string          `json:"policy_id"`
	Effect   store.Effect    `json:"effect"`
	Matched  bool            `json:"matched"`
	MatchWhy string          `json:"match_why"`
	Cond     map[string]bool `json:"condition_results"`
}

type authorizeResp struct {
	Decision string          `json:"decision"`
	Reason   string          `json:"reason"`
	Subject  string          `json:"subject"`
	Action   string          `json:"action"`
	Resource string          `json:"resource"`
	Trace    []ruleTraceJSON `json:"trace"`
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("method_not_allowed"))
		return
	}
	raw := bearerToken(r.Header.Get("Authorization"))
	if raw == "" {
		writeJSON(w, http.StatusForbidden, errBody("missing_credentials"))
		return
	}
	var req authorizeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Action == "" {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
		return
	}
	out, err := s.svc.Authorize(raw, req.Action, req.ResourceID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	resp := authorizeResp{
		Decision: string(out.Decision), Reason: string(out.Reason),
		Subject: out.Subject, Action: out.Action, Resource: out.Resource,
		Trace: make([]ruleTraceJSON, 0, len(out.Trace.Rules)),
	}
	for _, rt := range out.Trace.Rules {
		resp.Trace = append(resp.Trace, ruleTraceJSON{
			PolicyID: rt.PolicyID, Effect: rt.Effect, Matched: rt.Matched,
			MatchWhy: rt.MatchWhy, Cond: rt.CondResults,
		})
	}
	// 凭证有效但授权结论为 deny（默认/显式）同样是 403，但给出可区分原因与依据。
	if out.Decision == authz.DecisionPermit {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	writeJSON(w, http.StatusForbidden, resp)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("method_not_allowed"))
		return
	}
	entries := s.svc.Audit().Entries()
	writeJSON(w, http.StatusOK, map[string]any{"count": len(entries), "entries": entries})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errBody("method_not_allowed"))
		return
	}
	if err := s.svc.Audit().Verify(); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"status": "tampered", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "intact"})
}

func bearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func errBody(reason string) map[string]string {
	return map[string]string{"error": reason}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeServiceError 把服务层错误映射为稳定的 HTTP 状态与可区分原因。
func writeServiceError(w http.ResponseWriter, err error) {
	var ve *service.VerifyError
	if errors.As(err, &ve) {
		// 凭证/会话类拒绝：一律 403，原因字符串可区分且不泄漏细节。
		writeJSON(w, http.StatusForbidden, errBody(string(ve.Reason)))
		return
	}
	switch {
	case errors.Is(err, audit.ErrLogFull):
		// 审计不可写 => fail-closed 的系统不可用。
		writeJSON(w, http.StatusServiceUnavailable, errBody("audit_unavailable"))
	case errors.Is(err, store.ErrLimitExceeded):
		writeJSON(w, http.StatusServiceUnavailable, errBody("limit_exceeded"))
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
	case errors.Is(err, store.ErrAlreadyExists):
		writeJSON(w, http.StatusConflict, errBody("already_exists"))
	default:
		writeJSON(w, http.StatusInternalServerError, errBody("internal_error"))
	}
}
