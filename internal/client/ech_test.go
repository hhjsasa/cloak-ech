package client

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestECHConfigRefreshAndFallback(t *testing.T) {
	first, err := hex.DecodeString(testECHConfigListHex)
	require.NoError(t, err)
	second := bytes.Clone(first)
	second[20] ^= 1 // Rotate the public key while keeping a valid ECHConfigList.

	var version atomic.Int32
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/dns-message", r.Header.Get("Content-Type"))
		query := new(dns.Msg)
		require.NoError(t, query.Unpack(mustReadAll(t, r)))
		answer := new(dns.Msg)
		answer.SetReply(query)
		list := first
		if version.Load() == 1 {
			list = second
		}
		answer.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 10},
			Priority: 1, Target: ".", Value: []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: list}},
		}}}
		wire, err := answer.Pack()
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer server.Close()

	source, err := newECHConfigSource(server.URL, "", first)
	require.NoError(t, err)
	source.client = server.Client()
	now := time.Now()
	source.now = func() time.Time { return now }

	got, err := source.get("secret.example")
	require.NoError(t, err)
	require.Equal(t, first, got)
	require.EqualValues(t, 1, requests.Load())
	version.Store(1)
	got, err = source.get("secret.example")
	require.NoError(t, err)
	require.Equal(t, first, got)
	require.EqualValues(t, 1, requests.Load(), "cache should be used until TTL expires")

	now = now.Add(11 * time.Second)
	got, err = source.get("secret.example")
	require.NoError(t, err)
	require.Equal(t, second, got)
	require.EqualValues(t, 2, requests.Load())

	server.Close()
	now = now.Add(11 * time.Second)
	got, err = source.get("secret.example")
	require.NoError(t, err)
	require.Equal(t, second, got, "last known configuration should survive a DoH outage")
}

func TestECHRejectionRefresh(t *testing.T) {
	first, err := hex.DecodeString(testECHConfigListHex)
	require.NoError(t, err)
	second := bytes.Clone(first)
	second[20] ^= 1
	source, err := newECHConfigSource("https://127.0.0.1:1/dns-query", "", first)
	require.NoError(t, err)
	source.client.Timeout = 50 * time.Millisecond

	got, err := source.get("secret.example")
	require.NoError(t, err)
	require.Equal(t, first, got)
	source.reject("secret.example", first, second)
	got, err = source.get("secret.example")
	require.NoError(t, err)
	require.Equal(t, second, got, "authenticated retry configs should be used next")
	source.reject("secret.example", second, nil)
	_, err = source.get("secret.example")
	require.ErrorContains(t, err, "unable to obtain ECHConfigList", "a rejected config must not be reused")
}

func TestECHDoHUsesExplicitProxy(t *testing.T) {
	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connects.Add(1)
		require.Equal(t, http.MethodConnect, r.Method)
		require.Equal(t, "dns.example:443", r.Host)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()

	source, err := newECHConfigSource("https://dns.example/dns-query", proxy.URL, nil)
	require.NoError(t, err)
	_, err = source.get("secret.example")
	require.Error(t, err)
	require.EqualValues(t, 1, connects.Load())
}

func mustReadAll(t *testing.T, r *http.Request) []byte {
	t.Helper()
	var body bytes.Buffer
	_, err := body.ReadFrom(r.Body)
	require.NoError(t, err)
	return body.Bytes()
}
