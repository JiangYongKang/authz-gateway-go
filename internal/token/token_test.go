package token

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func sampleClaims(now time.Time) Claims {
	return Claims{
		Subject:   "alice",
		IssuedAt:  now.Unix(),
		Expires:   now.Add(time.Hour).Unix(),
		JTI:       "jti-1",
		SessionID: "sess-1",
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := NewSigner("k1", []byte("secret"), "local-issuer")
	raw, err := s.Sign(sampleClaims(now))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	c, err := Verify(raw, "k1", []byte("secret"), "local-issuer", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Subject != "alice" || c.JTI != "jti-1" {
		t.Fatalf("claims mismatch: %+v", c)
	}
}

func TestVerifyRejections(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := NewSigner("k1", []byte("secret"), "local-issuer")
	raw, err := s.Sign(sampleClaims(now))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		raw    string
		kid    string
		secret []byte
		issuer string
		at     time.Time
		want   error
	}{
		{"malformed", "not-a-jwt", "k1", []byte("secret"), "local-issuer", now, ErrMalformed},
		{"bad_signature", raw[:len(raw)-2] + "AA", "k1", []byte("secret"), "local-issuer", now, ErrBadSignature},
		{"wrong_key_secret", raw, "k1", []byte("other"), "local-issuer", now, ErrBadSignature},
		{"unknown_kid", raw, "k9", []byte("secret"), "local-issuer", now, ErrUnknownKey},
		{"issuer_mismatch", raw, "k1", []byte("secret"), "other-issuer", now, ErrIssuerMismatch},
		{"expired", raw, "k1", []byte("secret"), "local-issuer", now.Add(2 * time.Hour), ErrExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("input: token=%q kid=%q issuer=%q at=%v", tc.raw, tc.kid, tc.issuer, tc.at)
			_, err := Verify(tc.raw, tc.kid, tc.secret, tc.issuer, tc.at)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			t.Logf("decision basis: rejected with %v", err)
		})
	}
}

func TestAlgNoneRejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := NewSigner("k1", []byte("secret"), "local-issuer")
	raw, _ := s.Sign(sampleClaims(now))
	parts := strings.Split(raw, ".")
	forged := parts[0] + "." + parts[1] + "."
	_, err := Verify(forged, "k1", []byte("secret"), "local-issuer", now)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("alg=none style token must be rejected, got %v", err)
	}
}
