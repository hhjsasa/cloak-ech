package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const defaultECHDoHURL = "https://1.1.1.1/dns-query"
const fallbackECHDoHURL = "https://dns.google/dns-query"

type echCacheEntry struct {
	configList []byte
	expires    time.Time
}

// echConfigSource shares DNS results across all CDN connections. An optional
// static list is only a bootstrap when DoH is temporarily unavailable.
type echConfigSource struct {
	mu        sync.Mutex
	dohURLs   []string
	client    *http.Client
	bootstrap []byte
	cache     map[string]echCacheEntry
	rejected  map[string]map[string]struct{}
	now       func() time.Time
}

func newECHConfigSource(dohURL, proxyURL string, bootstrap []byte) (*echConfigSource, error) {
	urls := []string{defaultECHDoHURL, fallbackECHDoHURL}
	if dohURL != "" {
		urls = []string{dohURL}
	}
	for _, endpoint := range urls {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("ECHDoHURL must be an HTTPS URL: %q", endpoint)
		}
	}
	var proxy func(*http.Request) (*url.URL, error)
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
			(u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
			return nil, fmt.Errorf("ECHDoHProxy must be an HTTP, HTTPS, or SOCKS5 proxy URL: %q", proxyURL)
		}
		proxy = http.ProxyURL(u)
	}
	return &echConfigSource{
		dohURLs: urls,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				// An explicit proxy can bootstrap DoH when direct HTTPS is blocked.
				Proxy:             proxy,
				ForceAttemptHTTP2: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		bootstrap: bytes.Clone(bootstrap),
		cache:     make(map[string]echCacheEntry),
		rejected:  make(map[string]map[string]struct{}),
		now:       time.Now,
	}, nil
}

func (source *echConfigSource) get(serverName string) ([]byte, error) {
	source.mu.Lock()
	defer source.mu.Unlock()

	entry := source.cache[serverName]
	if len(entry.configList) > 0 && source.now().Before(entry.expires) {
		return bytes.Clone(entry.configList), nil
	}

	var lookupErr error
	for _, endpoint := range source.dohURLs {
		configList, ttl, err := source.lookup(endpoint, serverName)
		if err != nil {
			lookupErr = errors.Join(lookupErr, err)
			continue
		}
		if source.wasRejected(serverName, configList) {
			lookupErr = errors.Join(lookupErr, errors.New("DNS still advertises a rejected ECH config"))
			continue
		}
		source.cache[serverName] = echCacheEntry{bytes.Clone(configList), source.now().Add(ttl)}
		return configList, nil
	}

	if len(entry.configList) > 0 && !source.wasRejected(serverName, entry.configList) {
		return bytes.Clone(entry.configList), nil
	}
	if len(source.bootstrap) > 0 && !source.wasRejected(serverName, source.bootstrap) {
		return bytes.Clone(source.bootstrap), nil
	}
	return nil, fmt.Errorf("unable to obtain ECHConfigList for %s: %w", serverName, lookupErr)
}

// reject saves authenticated retry configs suggested by the CDN. The next
// connection uses them, while DNS is checked again after a short interval.
func (source *echConfigSource) reject(serverName string, used, retry []byte) {
	source.mu.Lock()
	defer source.mu.Unlock()

	if current := source.cache[serverName].configList; len(current) > 0 && !bytes.Equal(current, used) {
		return // another connection already refreshed the cache
	}
	if source.rejected[serverName] == nil {
		source.rejected[serverName] = make(map[string]struct{})
	}
	source.rejected[serverName][string(used)] = struct{}{}
	delete(source.cache, serverName)
	if len(retry) > 0 && !source.wasRejected(serverName, retry) {
		if _, err := newCDNTLSConn(&net.TCPConn{}, serverName, retry); err == nil {
			source.cache[serverName] = echCacheEntry{bytes.Clone(retry), source.now().Add(time.Minute)}
		}
	}
}

// wasRejected must be called with source.mu held.
func (source *echConfigSource) wasRejected(serverName string, list []byte) bool {
	_, rejected := source.rejected[serverName][string(list)]
	return rejected
}

func (source *echConfigSource) lookup(endpoint, serverName string) ([]byte, time.Duration, error) {
	name := dns.Fqdn(serverName)
	aliasTTL := time.Duration(-1)
	for hop := 0; hop < 4; hop++ {
		answer, err := source.query(endpoint, name)
		if err != nil {
			return nil, 0, err
		}
		var alias string
		for _, record := range answer.Answer {
			switch rr := record.(type) {
			case *dns.HTTPS:
				if !strings.EqualFold(rr.Hdr.Name, name) {
					continue
				}
				if rr.Priority == 0 {
					alias = rr.Target
					aliasTTL = minECHTTL(aliasTTL, rr.Hdr.Ttl)
					continue
				}
				for _, value := range rr.Value {
					if ech, ok := value.(*dns.SVCBECHConfig); ok && len(ech.ECH) > 0 {
						if _, err := newCDNTLSConn(&net.TCPConn{}, serverName, ech.ECH); err != nil {
							return nil, 0, fmt.Errorf("invalid ECHConfigList in HTTPS record: %w", err)
						}
						ttl := minECHTTL(aliasTTL, rr.Hdr.Ttl)
						if ttl < 5*time.Second {
							ttl = 5 * time.Second
						}
						return bytes.Clone(ech.ECH), ttl, nil
					}
				}
			case *dns.CNAME:
				if strings.EqualFold(rr.Hdr.Name, name) {
					alias = rr.Target
					aliasTTL = minECHTTL(aliasTTL, rr.Hdr.Ttl)
				}
			}
		}
		if alias == "" || alias == "." {
			return nil, 0, fmt.Errorf("no ECH configuration in HTTPS record for %s", name)
		}
		name = alias
	}
	return nil, 0, fmt.Errorf("too many HTTPS record aliases for %s", serverName)
}

func minECHTTL(previous time.Duration, ttl uint32) time.Duration {
	current := time.Duration(ttl) * time.Second
	if previous < 0 || current < previous {
		return current
	}
	return previous
}

func (source *echConfigSource) query(endpoint, name string) (*dns.Msg, error) {
	message := new(dns.Msg)
	message.SetQuestion(name, dns.TypeHTTPS)
	wire, err := message.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := source.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH returned HTTP %d", resp.StatusCode)
	}
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])); mediaType != "application/dns-message" {
		return nil, fmt.Errorf("DoH returned unexpected content type %q", mediaType)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(body); err != nil {
		return nil, err
	}
	if !answer.Response || answer.Truncated || answer.Id != message.Id || answer.Rcode != dns.RcodeSuccess ||
		len(answer.Question) != 1 || !strings.EqualFold(answer.Question[0].Name, name) ||
		answer.Question[0].Qtype != dns.TypeHTTPS || answer.Question[0].Qclass != dns.ClassINET {
		return nil, fmt.Errorf("invalid DoH response for %s (rcode %d)", name, answer.Rcode)
	}
	return answer, nil
}
