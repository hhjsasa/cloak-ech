package client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

type WSOverTLS struct {
	*common.WebSocketConn
	wsUrl         string
	echConfigList []byte
}

func newCDNTLSConn(rawConn net.Conn, serverName string, echConfigList []byte) (*utls.UConn, error) {
	utlsConfig := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: len(echConfigList) == 0,
	}
	if len(echConfigList) > 0 {
		utlsConfig.MinVersion = utls.VersionTLS13
		utlsConfig.EncryptedClientHelloConfigList = echConfigList
	}
	uconn := utls.UClient(rawConn, utlsConfig, utls.HelloChrome_Auto)
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
	uconn, err := newCDNTLSConn(rawConn, authInfo.MockDomain, ws.echConfigList)
	if err != nil {
		return
	}
	err = uconn.Handshake()
	if err != nil {
		return
	}
	if len(ws.echConfigList) > 0 && !uconn.ConnectionState().ECHAccepted {
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
	return nil
}
