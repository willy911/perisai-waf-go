// Package recaptcha memverifikasi token reCAPTCHA ke Google (server-side).
// Secret key tidak pernah ke browser — verifikasi selalu dari server WAF.
// Merupakan port dari perisai/recaptcha.py (Python).
package recaptcha

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VerifyURL adalah endpoint verifikasi Google. Merupakan variabel (bukan
// konstanta) agar test bisa mengarahkannya ke httptest server.
var VerifyURL = "https://www.google.com/recaptcha/api/siteverify"

// HTTPTimeout adalah batas waktu HTTP per verifikasi (sesuai kontrak ~10 dtk).
var HTTPTimeout = 10 * time.Second

type siteverifyResponse struct {
	Success    bool     `json:"success"`
	Score      float64  `json:"score"`
	ErrorCodes []string `json:"error-codes"`
}

// Verify memverifikasi token widget reCAPTCHA.
// Semantik v2 (minScore <= 0): sukses bila Google membalas success=true.
// Semantik v3 (minScore > 0): sukses bila success && score >= minScore.
func Verify(secret, token, remoteIP string, minScore float64) (bool, error) {
	if secret == "" {
		return false, errors.New("secret_key belum dikonfigurasi")
	}
	if token == "" {
		return false, errors.New("token kosong")
	}

	form := url.Values{
		"secret":   {secret},
		"response": {token},
		"remoteip": {remoteIP},
	}
	req, err := http.NewRequest(http.MethodPost, VerifyURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("gagal membuat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("gagal menghubungi Google: %w", err)
	}
	defer resp.Body.Close()

	var data siteverifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false, fmt.Errorf("gagal memparse respons Google: %w", err)
	}

	if !data.Success {
		codes := data.ErrorCodes
		if len(codes) == 0 {
			codes = []string{"unknown"}
		}
		return false, fmt.Errorf("verifikasi ditolak (%s)",
			strings.Join(codes, ", "))
	}
	if minScore > 0 && data.Score < minScore {
		return false, fmt.Errorf("skor %.2f di bawah ambang %.2f",
			data.Score, minScore)
	}
	return true, nil
}
