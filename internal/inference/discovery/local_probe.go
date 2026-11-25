package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"praxis/internal/domain"
	"praxis/internal/inference/providers"
)

type LocalProbeTarget struct {
	Label    string
	Provider string // "local" or "jev"
	BaseURL  string
}

type DetectedLocalServer struct {
	Label    string
	Provider string
	BaseURL  string
	Models   []string
}

func defaultLocalProbeTargets() []LocalProbeTarget {
	return []LocalProbeTarget{
		{Label: "Ollama", Provider: "local", BaseURL: "http://127.0.0.1:11434/v1"},
		{Label: "LM Studio", Provider: "local", BaseURL: "http://127.0.0.1:1234/v1"},
		{Label: "LiteLLM Proxy", Provider: "local", BaseURL: "http://127.0.0.1:4000/v1"},
		{Label: "Flide / OmniJev", Provider: "jev", BaseURL: "http://127.0.0.1:8000"},
	}
}

var localHandshakeClient = &http.Client{
	Timeout: 180 * time.Millisecond,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func parseDiscoveredModelIDs(body []byte) ([]string, bool) {
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, false
	}
	if payload.Data == nil && payload.Models == nil {
		return nil, false
	}
	seen := make(map[string]bool)
	var models []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			models = append(models, id)
		}
	}
	for _, d := range payload.Data {
		add(d.ID)
	}
	for _, m := range payload.Models {
		if m.ID != "" {
			add(m.ID)
		} else {
			add(m.Name)
		}
	}
	return models, true
}

func httpGetBody(ctx context.Context, client *http.Client, url, hdrName, hdrVal string, maxBytes int64) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if hdrName != "" && hdrVal != "" {
		req.Header.Set(hdrName, hdrVal)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	_ = resp.Body.Close()
	return resp.StatusCode, body, rerr
}

func probeSingleLocalTarget(ctx context.Context, target LocalProbeTarget) (DetectedLocalServer, bool) {
	base := strings.TrimRight(strings.TrimSpace(target.BaseURL), "/")
	if base == "" {
		return DetectedLocalServer{}, false
	}
	cctx, cancel := context.WithTimeout(ctx, 180*time.Millisecond)
	defer cancel()

	if target.Provider == "jev" {
		if code, body, err := httpGetBody(cctx, localHandshakeClient, base+"/v1/models", "", "", 32768); err == nil && code >= 200 && code < 300 {
			if models, ok := parseDiscoveredModelIDs(body); ok {
				return DetectedLocalServer{
					Label: target.Label, Provider: "jev", BaseURL: base, Models: append([]string{"jev-latest"}, models...),
				}, true
			}
		}
		if code, body, err := httpGetBody(cctx, localHandshakeClient, base+"/health", "", "", 8192); err == nil && code >= 200 && code < 300 {
			var h struct {
				Status string `json:"status"`
				Model  string `json:"model"`
			}
			if json.Unmarshal(body, &h) == nil && (h.Status == "ok" || h.Status == "loading") {
				models := []string{"jev-latest"}
				if m := strings.TrimSpace(h.Model); m != "" {
					models = append(models, m)
				}
				return DetectedLocalServer{
					Label: target.Label, Provider: "jev", BaseURL: base, Models: models,
				}, true
			}
		}
		return DetectedLocalServer{}, false
	}

	modelsURL := providers.ResolveOpenAIModelsURL(base)
	code, body, err := httpGetBody(cctx, localHandshakeClient, modelsURL, "", "", 128*1024)
	if err != nil || code < 200 || code >= 300 {
		return DetectedLocalServer{}, false
	}
	models, ok := parseDiscoveredModelIDs(body)
	if !ok {
		return DetectedLocalServer{}, false
	}
	return DetectedLocalServer{
		Label:    target.Label,
		Provider: "local",
		BaseURL:  base,
		Models:   models,
	}, true
}

// DiscoverOpenAIEndpoint queries /models on a configured local or gateway OpenAI-compatible URL without leaking stored keys across origins.
func DiscoverOpenAIEndpoint(ctx context.Context, rawCfg map[string]string, overrideURL, overrideKey string) ([]string, string) {
	savedURL := EnvOrDefault(rawCfg["local_model_url"], "LOCAL_MODEL_URL", "")
	targetURL := strings.TrimSpace(overrideURL)
	if targetURL == "" {
		targetURL = EnvOrDefault(savedURL, "", "http://127.0.0.1:11434/v1")
	}

	u, err := url.Parse(targetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, "invalid OpenAI-compatible endpoint URL"
	}

	apiKey := strings.TrimSpace(overrideKey)
	if apiKey == "" {
		sameSavedOrigin := savedURL != "" && SameURLOrigin(targetURL, savedURL)
		if overrideURL == "" || sameSavedOrigin {
			apiKey = EnvOrDefault(rawCfg["local_api_key"], "LOCAL_API_KEY", "")
			if apiKey == "" && (sameSavedOrigin || strings.EqualFold(u.Hostname(), "api.openai.com")) {
				apiKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
			}
		}
	}

	cctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	bearerVal := ""
	if apiKey != "" {
		bearerVal = "Bearer " + apiKey
	}
	modelsURL := providers.ResolveOpenAIModelsURL(targetURL)
	code, body, err := httpGetBody(cctx, systemOneClient, modelsURL, "Authorization", bearerVal, 4*1024*1024)
	if err != nil {
		return nil, fmt.Sprintf("endpoint unreachable (%s): %s", u.Host, domain.RedactSecretsWith(err.Error(), apiKey))
	}
	if code < 200 || code >= 300 {
		if summary := domain.SummarizeHTTPFailure(code, body, apiKey); summary != "" {
			return nil, fmt.Sprintf("GET /models HTTP %d (%s): %s", code, u.Host, summary)
		}
		return nil, fmt.Sprintf("GET /models returned HTTP %d from %s", code, u.Host)
	}
	models, ok := parseDiscoveredModelIDs(body)
	if !ok {
		return nil, fmt.Sprintf("invalid /models JSON payload from %s", u.Host)
	}
	return models, ""
}

func ProbeLocalInferenceServers(ctx context.Context, targets ...LocalProbeTarget) []DetectedLocalServer {
	list := targets
	if len(list) == 0 {
		list = defaultLocalProbeTargets()
	}
	results := make([]DetectedLocalServer, len(list))
	found := make([]bool, len(list))
	var wg sync.WaitGroup
	for i, tgt := range list {
		wg.Add(1)
		go func(idx int, t LocalProbeTarget) {
			defer wg.Done()
			if det, ok := probeSingleLocalTarget(ctx, t); ok {
				results[idx] = det
				found[idx] = true
			}
		}(i, tgt)
	}
	wg.Wait()

	var out []DetectedLocalServer
	for i, ok := range found {
		if ok {
			out = append(out, results[i])
		}
	}
	return out
}
