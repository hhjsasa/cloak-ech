package client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

type WSOverTLS struct {
	*common.WebSocketConn
	wsUrl     string
	echSource *echConfigSource
	rawConn   net.Conn
}

const cdnECHHandshakeTimeout = 15 * time.Second

func newCDNTLSConn(rawConn net.Conn, serverName string, echConfigList []byte) (*utls.UConn, error) {
	utlsConfig := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: len(echConfigList) == 0,
	}
	if len(echConfigList) > 0 {
		utlsConfig.MinVersion = utls.VersionTLS13
		utlsConfig.EncryptedClientHelloConfigList = echConfigList
	}
	helloID := utls.HelloChrome_Auto
	if len(echConfigList) > 0 {
		// Chrome's padded ClientHello is over 1,700 bytes with ECH. Firefox's
		// smaller hello is less likely to stall on paths that drop large flights.
		helloID = utls.HelloFirefox_Auto
	}
	uconn := utls.UClient(rawConn, utlsConfig, helloID)
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	for i, extension := range uconn.Extensions {
		_, ok := extension.(*utls.ALPNExtension)
		if ok {
			uconn.Extensions = append(uconn.Extensions[:i], uconn.Extensions[i+1:]...)
			break
		}
	}
	return uconn, nil
}

func (ws *WSOverTLS) Handshake(rawConn net.Conn, authInfo AuthInfo) (sessionKey [32]byte, err error) {
	ws.rawConn = rawConn
	var echConfigList []byte
	if ws.echSource != nil {
		echConfigList, err = ws.echSource.get(authInfo.MockDomain)
		if err != nil {
			return
		}
	}
	uconn, err := newCDNTLSConn(rawConn, authInfo.MockDomain, echConfigList)
	if err != nil {
		return
	}
	if ws.echSource != nil {
		if err = rawConn.SetDeadline(time.Now().Add(cdnECHHandshakeTimeout)); err != nil {
			return
		}
	}
	err = uconn.Handshake()
	if ws.echSource != nil {
		_ = rawConn.SetDeadline(time.Time{})
	}
	if err != nil {
		var rejected *utls.ECHRejectionError
		if ws.echSource != nil && errors.As(err, &rejected) {
			ws.echSource.reject(authInfo.MockDomain, echConfigList, rejected.RetryConfigList)
		}
		return
	}
	if ws.echSource != nil && !uconn.ConnectionState().ECHAccepted {
		return sessionKey, errors.New("CDN did not accept ECH")
	}

	u, err := url.Parse(ws.wsUrl)
	if err != nil {
		return sessionKey, fmt.Errorf("failed to parse ws url: %v", err)
	}

	payload, sharedSecret := makeAuthenticationPayload(authInfo)
	header := http.Header{}
	header.Add("hidden", base64.StdEncoding.EncodeToString(append(payload.randPubKey[:], payload.ciphertextWithTag[:]...)))
	c, _, err := websocket.NewClient(uconn, u, header, 16480, 16480)
	if err != nil {
		return sessionKey, fmt.Errorf("failed to handshake: %v", err)
	}

	ws.WebSocketConn = &common.WebSocketConn{Conn: c}

	buf := make([]byte, 128)
	n, err := ws.Read(buf)
	if err != nil {
		return sessionKey, fmt.Errorf("failed to read reply: %v", err)
	}

	if n != 60 {
		return sessionKey, errors.New("reply must be 60 bytes")
	}

	reply := buf[:60]
	sessionKeySlice, err := common.AESGCMDecrypt(reply[:12], sharedSecret[:], reply[12:])
	if err != nil {
		return
	}
	copy(sessionKey[:], sessionKeySlice)

	return
}

func (ws *WSOverTLS) Close() error {
	if ws.WebSocketConn != nil {
		return ws.WebSocketConn.Close()
	}
	if ws.rawConn != nil {
		return ws.rawConn.Close()
	}
	return nil
}
