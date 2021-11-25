package liboidcagent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

type keyring struct {
	ClientPrivate *[32]byte
	ClientPublic  *[32]byte
	ServerPublic  *[32]byte
}

type agentConnection struct {
	Conn    net.Conn
	Keyring *keyring
	Remote  bool
	Socket  *socket
}

const defaultRemotePort = 42424

type socket struct {
	AddressEnvVar string
	Type          string // e.g.: "unix" or "tcp"
	Remote        bool
}

// we try these sockets in order
var sockets = []socket{
	{
		"OIDC_SOCK",
		"unix",
		false,
	},
	{
		"OIDC_REMOTE_SOCK",
		"tcp",
		true,
	},
}

func (c *agentConnection) openSocket() (err error) {
	for i, socket := range sockets {
		address, ok := os.LookupEnv(socket.AddressEnvVar)
		if !ok {
			err = fmt.Errorf("$%s not set", socket.AddressEnvVar)
			continue
		}

		if socket.Remote {
			if _, port, _ := net.SplitHostPort(address); port == "" {
				address = fmt.Sprintf("%s:%d", address, defaultRemotePort)
			}
		}

		c.Conn, err = net.Dial(socket.Type, address)
		if err != nil {
			err = fmt.Errorf("dialing socket: %s", err)
		} else {
			c.Socket = &sockets[i]
			return
		}
	}
	// err is not nil here
	err = fmt.Errorf("no socket connection! last error was: %s", err)
	return
}

func communicateWithSock(c net.Conn, request []byte) (response []byte, err error) {
	_, err = c.Write(request)
	if err != nil {
		err = fmt.Errorf("writing to socket: %s", err)
		return
	}
	bufSize := 4096
	buffer := make([]byte, bufSize)
	for {
		n, e := c.Read(buffer)
		response = append(response, buffer[:n]...)
		if n < bufSize || e != nil {
			err = e
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("reading from socket: %s", err)
	}
	return
}

// init opens a socket connection to oidc-agent.
// use with `defer conn.close()` in order to not leak the socket
func (c *agentConnection) init(encrypted bool) (err error) {
	err = c.openSocket()
	if err != nil {
		return
	}

	if encrypted {
		c.Keyring = new(keyring)
		err = c.Keyring.init(c.Conn)
	}
	return
}

func newEncryptedConn() (c *agentConnection, err error) {
	c = new(agentConnection)
	err = c.init(true)
	return
}

func (c *agentConnection) close() error {
	return c.Conn.Close()
}

func (c *agentConnection) sendRequest(request []byte) (response []byte, err error) {
	msg := request
	if c.Keyring != nil {
		msg, err = c.Keyring.encryptMessage(request)
		if err != nil {
			return
		}
	}

	response, err = communicateWithSock(c.Conn, msg)
	if err != nil {
		return
	}

	if c.Keyring != nil {
		response, err = c.Keyring.decryptMessage(response)
	}

	return
}

func (c *agentConnection) sendJSONRequest(req interface{}, resp interface{}) (err error) {
	var reqMsg []byte
	reqMsg, err = json.Marshal(req)
	if err != nil {
		return
	}
	var respMsg []byte
	respMsg, err = c.sendRequest(reqMsg)
	if err != nil {
		return
	}
	err = json.Unmarshal(respMsg, resp)
	return
}

func (k *keyring) init(c net.Conn) (err error) {
	k.ClientPublic, k.ClientPrivate, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	clientPubKeyBase64 := []byte(base64.StdEncoding.EncodeToString(k.ClientPublic[:]))
	serverPubKeyBase64, err := communicateWithSock(c, clientPubKeyBase64)
	if err != nil {
		return
	}
	var serverPubKeyBytes []byte
	serverPubKeyBytes, err = base64.StdEncoding.DecodeString(string(serverPubKeyBase64))
	if err != nil {
		return
	}
	k.ServerPublic = sliceToArray32(serverPubKeyBytes)
	return
}

func (k *keyring) encryptMessage(message []byte) (encryptedMsg []byte, err error) {
	var nonce [24]byte
	_, err = io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return
	}
	encrypted := box.Seal([]byte{}, message, &nonce, k.ServerPublic, k.ClientPrivate)
	encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce[:])
	msgLen := len(message)
	encryptedMsg = []byte(fmt.Sprintf("%d:%s:%s", msgLen, nonceBase64, encryptedBase64))
	return
}

func (k *keyring) decryptMessage(message []byte) (decrypted []byte, err error) {
	split := strings.Split(string(message), ":")
	var nonce []byte
	nonce, err = base64.StdEncoding.DecodeString(split[1])
	if err != nil {
		return
	}
	var encryptedRes []byte
	encryptedRes, err = base64.StdEncoding.DecodeString(split[2])
	if err != nil {
		return
	}
	res, ok := box.Open([]byte{}, encryptedRes, sliceToArray24(nonce), k.ServerPublic, k.ClientPrivate)
	decrypted = res
	if !ok {
		err = fmt.Errorf("decryption error")
	}
	return
}

func sliceToArray32(slice []byte) *[32]byte {
	arr := [32]byte{}
	copy(arr[:], slice)
	return &arr
}

func sliceToArray24(slice []byte) *[24]byte {
	arr := [24]byte{}
	copy(arr[:], slice)
	return &arr
}
