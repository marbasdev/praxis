package domain

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
)

var (
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`prx_[0-9a-fA-F]{24,}`),
		regexp.MustCompile(`AIza[0-9A-Za-z_-]{20,}`),
		regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`),
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	}
	htmlTitleRe   = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	htmlTagRe     = regexp.MustCompile(`<[^>]+>`)
	htmlCommentRe = regexp.MustCompile(`(?s)^(?:<!--.*?-->\s*)+`)
)

var injectionPhrases = []string{
	"ignore previous instructions",
	"ignore all prior instructions",
	"disregard all previous rules",
	"system prompt override",
	"이전 지시를 모두 무시",
}

func CheckSecurityGuard(text string) string {
	for _, re := range secretPatterns {
		if re.MatchString(text) {
			return "raw API key or private key detected"
		}
	}
	lower := strings.ToLower(text)
	for _, p := range injectionPhrases {
		if strings.Contains(lower, p) {
			return "prompt injection pattern detected"
		}
	}
	return ""
}

func RedactSecrets(raw string) string {
	s := raw
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

func RedactSecretsWith(raw string, extraSecrets ...string) string {
	s := RedactSecrets(raw)
	for _, sec := range extraSecrets {
		trimmed := strings.TrimSpace(sec)
		if len(trimmed) >= 6 {
			s = strings.ReplaceAll(s, trimmed, "[REDACTED]")
		}
	}
	return s
}

func collapseSingleLine(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

func looksLikeHTMLPayload(s string) bool {
	cleaned := strings.TrimSpace(strings.TrimPrefix(s, "\ufeff"))
	cleaned = strings.TrimSpace(htmlCommentRe.ReplaceAllString(cleaned, ""))
	low := strings.ToLower(cleaned)
	if low == "" {
		return false
	}
	for _, pfx := range []string{"<!doctype html", "<html", "<head", "<body"} {
		if strings.HasPrefix(low, pfx) {
			return true
		}
	}
	return strings.Contains(low, "</html>") ||
		strings.Contains(low, "</head>") ||
		(strings.Contains(low, "<head") && strings.Contains(low, "<body"))
}

// SummarizeHTTPFailure extracts structured JSON errors, replaces raw proxy/gateway HTML pages
// with a readable status summary, and redacts secret tokens before returning.
func SummarizeHTTPFailure(status int, rawBody []byte, extraSecrets ...string) string {
	trimmed := strings.TrimSpace(string(rawBody))
	if trimmed == "" {
		if status == http.StatusRequestEntityTooLarge {
			return "request payload too large (HTTP 413 — gateway/proxy rejected body size)"
		}
		return ""
	}

	var structured struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
		Detail  any             `json:"detail"`
	}
	if json.Unmarshal(rawBody, &structured) == nil {
		msg := ""
		if len(structured.Error) > 0 {
			var errObj struct {
				Message string `json:"message"`
			}
			var errStr string
			if json.Unmarshal(structured.Error, &errObj) == nil && strings.TrimSpace(errObj.Message) != "" {
				msg = errObj.Message
			} else if json.Unmarshal(structured.Error, &errStr) == nil && strings.TrimSpace(errStr) != "" {
				msg = errStr
			}
		}
		if msg == "" && strings.TrimSpace(structured.Message) != "" {
			msg = structured.Message
		}
		if msg == "" {
			if ds, ok := structured.Detail.(string); ok && strings.TrimSpace(ds) != "" {
				msg = ds
			}
		}
		if msg != "" {
			clean := RedactSecretsWith(collapseSingleLine(msg), extraSecrets...)
			return TruncateUTF8Bytes(clean, 360)
		}
	}

	if looksLikeHTMLPayload(trimmed) {
		title := ""
		if m := htmlTitleRe.FindStringSubmatch(trimmed); len(m) >= 2 {
			title = collapseSingleLine(html.UnescapeString(htmlTagRe.ReplaceAllString(m[1], " ")))
		}
		title = RedactSecretsWith(title, extraSecrets...)
		if status == http.StatusRequestEntityTooLarge {
			if title != "" {
				return fmt.Sprintf("request payload too large (%s — gateway/proxy rejected body size)", TruncateUTF8Bytes(title, 120))
			}
			return "request payload too large (HTTP 413 — gateway/proxy rejected body size)"
		}
		if title != "" {
			return fmt.Sprintf("%s (HTML proxy/gateway error page)", TruncateUTF8Bytes(title, 160))
		}
		if st := http.StatusText(status); st != "" {
			return fmt.Sprintf("%s (HTML proxy/gateway error page)", st)
		}
		return "upstream returned HTML error page"
	}

	clean := RedactSecretsWith(collapseSingleLine(trimmed), extraSecrets...)
	return TruncateUTF8Bytes(clean, 360)
}
