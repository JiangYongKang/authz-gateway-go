// Package httpserver 把网关能力暴露为本地 HTTP JSON 接口。
// 所有入口共享同一套校验与判定逻辑，因此不同入口下结论与拒绝原因一致。
//
// 路由：
//
//	POST /v1/tokens/issue           签发凭证
//	POST /v1/tokens/verify          只校验凭证
//	POST /v1/tokens/renew           续期凭证
//	POST /v1/sessions/revoke        按 session_id 撤销
//	POST /v1/tokens/revoke          按凭证撤销其会话
//	POST /v1/authorize              凭证 + 资源 + 动作判定
//	GET  /v1/audit?after_id=N       查询审计记录
//	GET  /v1/audit/export?from=&to= 导出自包含审计证据（可离线核验）
//	GET  /v1/keys                   查询密钥元数据（无明文）
//	POST /v1/admin/policies         upsert 策略
//	DELETE /v1/admin/policies/{id}  删除策略
//	POST /v1/admin/users/roles      覆盖用户角色
//	POST /v1/admin/keys/prepare     登记下一任密钥
//	POST /v1/admin/keys/rotate      执行轮换
//	POST /v1/admin/keys/retire      彻底退役历史密钥
package httpserver

import (
	"encoding/json"
	"net/http"

	"github.com/highcumontoa/authz-gateway-go/internal/gateway"
)

// Server 持有网关与路由。
type Server struct {
	gw *gateway.Gateway
}

// New 构造 HTTP 服务。
func New(gw *gateway.Gateway) *Server { return &Server{gw: gw} }

// Handler 返回装配好路由的 http.Handler。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/tokens/issue", s.issue)
	mux.HandleFunc("POST /v1/tokens/verify", s.verify)
	mux.HandleFunc("POST /v1/tokens/renew", s.renew)
	mux.HandleFunc("POST /v1/sessions/revoke", s.revoke)
	mux.HandleFunc("POST /v1/tokens/revoke", s.revokeByToken)
	mux.HandleFunc("POST /v1/authorize", s.authorize)
	mux.HandleFunc("GET /v1/audit", s.audit)
	mux.HandleFunc("GET /v1/audit/export", s.auditExport)
	mux.HandleFunc("GET /v1/keys", s.listKeys)
	mux.HandleFunc("POST /v1/admin/policies", s.upsertPolicy)
	mux.HandleFunc("DELETE /v1/admin/policies/{id}", s.deletePolicy)
	mux.HandleFunc("POST /v1/admin/users/roles", s.assignRoles)
	mux.HandleFunc("POST /v1/admin/keys/prepare", s.prepareKey)
	mux.HandleFunc("POST /v1/admin/keys/rotate", s.rotate)
	mux.HandleFunc("POST /v1/admin/keys/retire", s.retireKey)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

type issueReq struct {
	Username   string            `json:"username"`
	Attributes map[string]string `json:"attributes"`
}

func (s *Server) issue(w http.ResponseWriter, r *http.Request) {
	var in issueReq
	if !decode(w, r, &in) {
		return
	}
	res, err := s.gw.Issue(r.Context(), gateway.IssueRequest{
		Username: in.Username, Attributes: in.Attributes,
	})
	if err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": res.Token, "jti": res.JTI,
		"session_id": res.SessionID, "expires_at": res.ExpiresAt,
	})
}

type tokenReq struct {
	Token string `json:"token"`
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	var in tokenReq
	if !decode(w, r, &in) {
		return
	}
	res := s.gw.Verify(r.Context(), in.Token)
	status := http.StatusOK
	if !res.Valid {
		status = http.StatusForbidden
	}
	writeJSON(w, status, res)
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	var in tokenReq
	if !decode(w, r, &in) {
		return
	}
	res, err := s.gw.Renew(r.Context(), in.Token)
	if err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": res.Token, "jti": res.JTI,
		"session_id": res.SessionID, "expires_at": res.ExpiresAt,
	})
}

type revokeReq struct {
	SessionID string `json:"session_id"`
	Token     string `json:"token"`
	Actor     string `json:"actor"`
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	var in revokeReq
	if !decode(w, r, &in) {
		return
	}
	if err := s.gw.Revoke(r.Context(), in.SessionID, actorOr(in.Actor)); err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) revokeByToken(w http.ResponseWriter, r *http.Request) {
	var in revokeReq
	if !decode(w, r, &in) {
		return
	}
	if err := s.gw.RevokeByToken(r.Context(), in.Token, actorOr(in.Actor)); err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

type authorizeReq struct {
	Token      string            `json:"token"`
	Resource   string            `json:"resource"`
	Action     string            `json:"action"`
	Attributes map[string]string `json:"attributes"`
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	var in authorizeReq
	if !decode(w, r, &in) {
		return
	}
	res := s.gw.Authorize(r.Context(), gateway.AuthorizeRequest{
		Token:      in.Token,
		Resource:   in.Resource,
		Action:     in.Action,
		Attributes: in.Attributes,
	})
	status := http.StatusOK
	if !res.Allowed {
		status = http.StatusForbidden
	}
	writeJSON(w, status, res)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	after := int64(0)
	if v := r.URL.Query().Get("after_id"); v != "" {
		if !parseInt64(w, v, &after) {
			return
		}
	}
	events, err := s.gw.AuditSince(after)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("audit_failure", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

// auditExport 导出自包含审计证据。范围不合法 => 400，超上限 => 413，
// 其它审计故障 => 503；失败时绝不返回半成品产物。
func (s *Server) auditExport(w http.ResponseWriter, r *http.Request) {
	var from, to int64
	if !parseInt64(w, r.URL.Query().Get("from"), &from) {
		return
	}
	if !parseInt64(w, r.URL.Query().Get("to"), &to) {
		return
	}
	ev, err := s.gw.ExportAudit(from, to)
	if err != nil {
		switch gateway.ExportReasonOf(err) {
		case gateway.ReasonExportRangeInvalid:
			writeJSON(w, http.StatusBadRequest, errBody(gateway.ReasonExportRangeInvalid, err.Error()))
		case gateway.ReasonExportLimit:
			writeJSON(w, http.StatusRequestEntityTooLarge, errBody(gateway.ReasonExportLimit, err.Error()))
		default:
			writeJSON(w, http.StatusServiceUnavailable, errBody("audit_failure", err.Error()))
		}
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.gw.ListKeys(r.Context())
	if err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

type policyReq struct {
	Actor  string              `json:"actor"`
	Policy gateway.PolicyInput `json:"policy"`
}

func (s *Server) upsertPolicy(w http.ResponseWriter, r *http.Request) {
	var in policyReq
	if !decode(w, r, &in) {
		return
	}
	p, err := s.gw.UpsertPolicy(r.Context(), in.Policy, actorOr(in.Actor))
	if err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	actor := r.URL.Query().Get("actor")
	if err := s.gw.DeletePolicy(r.Context(), r.PathValue("id"), actorOr(actor)); err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type rolesReq struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Actor    string   `json:"actor"`
}

func (s *Server) assignRoles(w http.ResponseWriter, r *http.Request) {
	var in rolesReq
	if !decode(w, r, &in) {
		return
	}
	if err := s.gw.AssignRoles(r.Context(), in.Username, in.Roles, actorOr(in.Actor)); err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

type keyReq struct {
	Kid    string `json:"kid"`
	Secret string `json:"secret,omitempty"`
	Actor  string `json:"actor"`
}

func (s *Server) prepareKey(w http.ResponseWriter, r *http.Request) {
	var in keyReq
	if !decode(w, r, &in) {
		return
	}
	if err := s.gw.PrepareKey(r.Context(), in.Kid, []byte(in.Secret), actorOr(in.Actor)); err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "prepared", "kid": in.Kid})
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	var in keyReq
	if !decode(w, r, &in) {
		return
	}
	kid, err := s.gw.Rotate(r.Context(), in.Kid, actorOr(in.Actor))
	if err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"active_kid": kid})
}

func (s *Server) retireKey(w http.ResponseWriter, r *http.Request) {
	var in keyReq
	if !decode(w, r, &in) {
		return
	}
	if err := s.gw.RetireKey(r.Context(), in.Kid, actorOr(in.Actor)); err != nil {
		writeGatewayError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "retired", "kid": in.Kid})
}

func actorOr(a string) string {
	if a == "" {
		return "anonymous-admin"
	}
	return a
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "invalid JSON body"))
		return false
	}
	return true
}

func errBody(reason, msg string) map[string]string {
	return map[string]string{"error": msg, "reason": reason}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeGatewayError 把网关错误映射为 HTTP 状态与统一原因码：
// 被拒绝 => 403；请求非法 => 400；审计/存储故障 => 503（调用方应重试或告警，
// 而不是放行）。任何错误都不降级为 200。
func writeGatewayError(w http.ResponseWriter, err error) {
	reason := gateway.ReasonOf(err)
	switch reason {
	case "user_not_found", "bad_request":
		writeJSON(w, http.StatusBadRequest, errBody(reason, err.Error()))
	case "storage_failure", "audit_failure":
		writeJSON(w, http.StatusServiceUnavailable, errBody(reason, err.Error()))
	case "limit_exceeded":
		writeJSON(w, http.StatusTooManyRequests, errBody(reason, err.Error()))
	default:
		writeJSON(w, http.StatusForbidden, errBody(reason, err.Error()))
	}
}
