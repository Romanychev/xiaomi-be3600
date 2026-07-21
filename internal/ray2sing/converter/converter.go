// Package converter turns vless:// share links into sing-box outbound
// options. Другие протоколы не поддерживаются намеренно: на роутер ставится
// slim-сборка sing-box, в которой скомпилирован только vless
// (см. scripts/build-singbox.sh).
package converter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/romanychev/be3600/internal/ray2sing/option"
)

type Service struct{}

// Outbounds parses newline-separated share links into sing-box outbounds.
func Outbounds(content string) ([]option.Outbound, error) {
	var result []option.Outbound
	for i, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields, err := parseLink(line)
		if err != nil {
			return nil, fmt.Errorf("link %d: %w", i+1, err)
		}
		if fields["tag"] == "" {
			fields["tag"] = fmt.Sprintf("%v-%d", fields["type"], len(result)+1)
		}
		outbound, err := option.FromMap(fields)
		if err != nil {
			return nil, fmt.Errorf("link %d: %w", i+1, err)
		}
		result = append(result, outbound)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no proxy links found")
	}
	return result, nil
}

func parseLink(link string) (map[string]any, error) {
	if strings.HasPrefix(link, "vless://") {
		return parseVless(link)
	}
	scheme, _, _ := strings.Cut(link, "://")
	return nil, fmt.Errorf("unsupported link type %q: only vless:// links are supported", scheme)
}

func parseVless(link string) (map[string]any, error) {
	u, port, err := parseURL(link)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("vless link is missing uuid")
	}
	q := u.Query()
	fields := map[string]any{
		"type":        "vless",
		"tag":         tagFromFragment(u),
		"server":      u.Hostname(),
		"server_port": port,
		"uuid":        u.User.Username(),
	}
	if flow := q.Get("flow"); flow != "" {
		fields["flow"] = flow
	}
	if transport := transportOptions(q.Get("type"), q.Get("host"), q.Get("path"), q.Get("serviceName")); transport != nil {
		fields["transport"] = transport
	}
	if tls := tlsFromQuery(q, u.Hostname(), false); tls != nil {
		fields["tls"] = tls
	}
	return fields, nil
}

func transportOptions(network, host, path, serviceName string) map[string]any {
	switch network {
	case "ws":
		transport := map[string]any{"type": "ws"}
		if path != "" {
			// Some links pack early-data into the path as ?ed=2048.
			if rawPath, _, found := strings.Cut(path, "?ed="); found {
				transport["path"] = rawPath
				transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
			} else {
				transport["path"] = path
			}
		}
		if host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
		return transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if name := firstNonEmpty(serviceName, path); name != "" {
			transport["service_name"] = name
		}
		return transport
	case "h2", "http":
		transport := map[string]any{"type": "http"}
		if host != "" {
			transport["host"] = strings.Split(host, ",")
		}
		if path != "" {
			transport["path"] = path
		}
		return transport
	case "httpupgrade":
		transport := map[string]any{"type": "httpupgrade"}
		if host != "" {
			transport["host"] = host
		}
		if path != "" {
			transport["path"] = path
		}
		return transport
	default:
		return nil
	}
}

func tlsFromQuery(q url.Values, serverHost string, forceEnabled bool) map[string]any {
	security := q.Get("security")
	if !forceEnabled && security != "tls" && security != "reality" && security != "xtls" {
		return nil
	}
	tls := map[string]any{"enabled": true}
	if sni := firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("host"), serverHost); sni != "" {
		tls["server_name"] = sni
	}
	if isTruthy(firstNonEmpty(q.Get("allowInsecure"), q.Get("insecure"))) {
		tls["insecure"] = true
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if fp := q.Get("fp"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if pbk := q.Get("pbk"); pbk != "" {
		reality := map[string]any{"enabled": true, "public_key": pbk}
		if sid := q.Get("sid"); sid != "" {
			reality["short_id"] = sid
		}
		tls["reality"] = reality
	}
	return tls
}

func parseURL(link string) (*url.URL, int, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid link: %w", err)
	}
	if u.Hostname() == "" {
		return nil, 0, fmt.Errorf("link is missing server address")
	}
	port, err := toPort(u.Port())
	if err != nil {
		return nil, 0, err
	}
	return u, port, nil
}

func tagFromFragment(u *url.URL) string {
	return strings.TrimSpace(u.Fragment)
}

func toPort(v any) (int, error) {
	port := toIntDefault(v, 0)
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port %v", v)
	}
	return port, nil
}

func toIntDefault(v any, fallback int) int {
	switch value := v.(type) {
	case float64:
		return int(value)
	case int:
		return value
	case json.Number:
		if n, err := value.Int64(); err == nil {
			return int(n)
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return n
		}
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func isTruthy(s string) bool {
	return s == "1" || strings.EqualFold(s, "true")
}
