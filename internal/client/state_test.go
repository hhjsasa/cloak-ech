package client

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"testing"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/stretchr/testify/assert"
)

// ECHConfigList test vector from uTLS's ECH parser tests.
const testECHConfigListHex = "0045fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000"

func testCDNRawConfig() RawConfig {
	return RawConfig{
		Transport:        "CDN",
		ServerName:       "secret.example",
		ProxyMethod:      "shadowsocks",
		EncryptionMethod: "plain",
		UID:              []byte("test-user-id"),
		PublicKey:        []byte{9, 180, 32, 136, 15, 190, 237, 243, 91, 55, 5, 41, 49, 118, 127, 168, 120, 223, 162, 205, 215, 101, 210, 222, 173, 208, 98, 10, 196, 172, 231, 255},
		LocalHost:        "127.0.0.1",
		LocalPort:        "1080",
		RemoteHost:       "cdn.example",
		RemotePort:       "443",
	}
}

func TestCDNECHConfig(t *testing.T) {
	configList, err := hex.DecodeString(testECHConfigListHex)
	assert.NoError(t, err)

	config := testCDNRawConfig()
	_, remote, _, err := config.ProcessRawConfig(common.RealWorldState)
	assert.NoError(t, err)
	assert.Nil(t, remote.Transport.echSource)

	config.EnableECH = true
	_, remote, _, err = config.ProcessRawConfig(common.RealWorldState)
	assert.NoError(t, err)
	assert.NotNil(t, remote.Transport.echSource)
	assert.Empty(t, remote.Transport.echSource.bootstrap)

	config.ECHConfigList = "not-base64"
	_, _, _, err = config.ProcessRawConfig(common.RealWorldState)
	assert.ErrorContains(t, err, "base64")

	config.ECHConfigList = base64.StdEncoding.EncodeToString([]byte("invalid list"))
	_, _, _, err = config.ProcessRawConfig(common.RealWorldState)
	assert.ErrorContains(t, err, "invalid ECHConfigList")

	config.ECHConfigList = base64.StdEncoding.EncodeToString(configList)
	_, remote, _, err = config.ProcessRawConfig(common.RealWorldState)
	assert.NoError(t, err)
	assert.Equal(t, configList, remote.Transport.echSource.bootstrap)
	assert.Same(t, remote.Transport.echSource, remote.Transport.CreateTransport().(*WSOverTLS).echSource)

	config.ECHDoHURL = "http://insecure.example/dns-query"
	_, _, _, err = config.ProcessRawConfig(common.RealWorldState)
	assert.ErrorContains(t, err, "HTTPS URL")
	config.ECHDoHURL = ""
	config.ECHDoHProxy = "socks5://127.0.0.1:1080"
	_, remote, _, err = config.ProcessRawConfig(common.RealWorldState)
	assert.NoError(t, err)
	assert.NotNil(t, remote.Transport.echSource)
	config.ECHDoHProxy = "file:///tmp/proxy"
	_, _, _, err = config.ProcessRawConfig(common.RealWorldState)
	assert.ErrorContains(t, err, "ECHDoHProxy")
	config.ECHDoHProxy = ""

	config.ServerName = "random"
	_, _, _, err = config.ProcessRawConfig(common.RealWorldState)
	assert.ErrorContains(t, err, "fixed ServerName")
	config.ServerName = "secret.example"

	config.Transport = "direct"
	_, _, _, err = config.ProcessRawConfig(common.RealWorldState)
	assert.ErrorContains(t, err, "requires CDN transport")
}

func TestSSVEnableECH(t *testing.T) {
	configJSON := ssvToJson("Transport=CDN;EnableECH=true;ECHConfigList=Zm9v")
	assert.Contains(t, string(configJSON), `"EnableECH":true`)
	assert.Contains(t, string(configJSON), `"ECHConfigList":"Zm9v"`)
}

func TestCDNECHOuterClientHello(t *testing.T) {
	configList, err := hex.DecodeString(testECHConfigListHex)
	assert.NoError(t, err)
	uconn, err := newCDNTLSConn(nil, "secret.example", configList)
	assert.NoError(t, err)
	assert.NoError(t, uconn.MarshalClientHello())
	outer := uconn.HandshakeState.Hello.Raw
	assert.Contains(t, string(outer), "cloudflare-ech.com")
	assert.False(t, bytes.Contains(outer, []byte("secret.example")), "inner SNI leaked in ClientHelloOuter")
}

func TestParseConfig(t *testing.T) {
	ssv := "UID=iGAO85zysIyR4c09CyZSLdNhtP/ckcYu7nIPI082AHA=;PublicKey=IYoUzkle/T/kriE+Ufdm7AHQtIeGnBWbhhlTbmDpUUI=;" +
		"ServerName=www.bing.com;NumConn=4;MaskBrowser=chrome;ProxyMethod=shadowsocks;EncryptionMethod=plain"
	json := ssvToJson(ssv)
	expected := []byte(`{"UID":"iGAO85zysIyR4c09CyZSLdNhtP/ckcYu7nIPI082AHA=","PublicKey":"IYoUzkle/T/kriE+Ufdm7AHQtIeGnBWbhhlTbmDpUUI=","ServerName":"www.bing.com","NumConn":4,"MaskBrowser":"chrome","ProxyMethod":"shadowsocks","EncryptionMethod":"plain"}`)

	t.Run("byte equality", func(t *testing.T) {
		assert.Equal(t, expected, json)
	})

	t.Run("struct equality", func(t *testing.T) {
		tmpConfig, _ := ioutil.TempFile("", "ck_client_config")
		_, _ = tmpConfig.Write(expected)
		parsedFromSSV, err := ParseConfig(ssv)
		assert.NoError(t, err)
		parsedFromJson, err := ParseConfig(tmpConfig.Name())
		assert.NoError(t, err)

		assert.Equal(t, parsedFromJson, parsedFromSSV)
	})

	t.Run("empty file", func(t *testing.T) {
		tmpConfig, _ := ioutil.TempFile("", "ck_client_config")
		_, err := ParseConfig(tmpConfig.Name())
		assert.Error(t, err)
	})

}
