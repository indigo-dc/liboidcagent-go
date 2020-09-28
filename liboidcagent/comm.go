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

func communicateWithSock(c net.Conn, request string) (response []byte, err error) {
	_, err = c.Write([]byte(request))
	if err != nil {
		err = fmt.Errorf("Writing to socket: %s", err)
		return
	}
	for {
		buffer := make([]byte, 4096)
		n, e := c.Read(buffer)
		response = append(response, buffer[:n]...)
		if n < 4096 || e != nil {
			err = e
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("Reading from socket: %s", err)
	}
	return
}

func initCommunication(remote bool) (c net.Conn, err error) {
	envVar := "OIDC_SOCK"
	sockType := "unix"
	if remote {
		envVar = "OIDC_REMOTE_SOCK"
		sockType = "tcp"
	}
	socketValue, socketSet := os.LookupEnv(envVar)
	if !socketSet {
		err = fmt.Errorf("$%s not set", envVar)
		return
	}

	if remote {
		if _, port, _ := net.SplitHostPort(socketValue); port == "" {
			socketValue = fmt.Sprintf("%s:%d", socketValue, 42424)
		}
	}

	c, err = net.Dial(sockType, socketValue)
	if err != nil {
		err = fmt.Errorf("Dialing socket: %s", err)
		return
	}
	return
}

func communicatePlain(remote bool, request string) (response string, err error) {
	c, err := initCommunication(remote)
	if err != nil {
		return
	}
	defer c.Close()

	res, err := communicateWithSock(c, request)
	response = string(res)
	return
}

func communicateEncrypted(remote bool, request string) (response string, err error) {
	c, err := initCommunication(remote)
	if err != nil {
		return
	}
	defer c.Close()

	clientPrivateKey, _, serverPublicKey, err := initKeys(c)
	if err != nil {
		return
	}

	encryptedMsg, err := encryptMessage(request, serverPublicKey, clientPrivateKey)
	if err != nil {
		return
	}

	encryptedResponse, err := communicateWithSock(c, encryptedMsg)
	if err != nil {
		return
	}
	encryptedResponseStr := string(encryptedResponse)
	if isJSON(encryptedResponseStr) {
		// response not encrypted
		response = encryptedResponseStr
		return
	}

	response, err = decryptMessage(encryptedResponseStr, serverPublicKey, clientPrivateKey)
	return
}

func initKeys(c net.Conn) (clientPrivateKey, clientPublicKey, serverPublicKey *[32]byte, err error) {
	clientPublicKey, clientPrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	clientPubKeyBase64 := base64.StdEncoding.EncodeToString(clientPublicKey[:])
	serverPubKeyBase64, err := communicateWithSock(c, clientPubKeyBase64)
	if err != nil {
		return
	}
	serverPubKeyB, err := decodeBytes(serverPubKeyBase64)
	if err != nil {
		return
	}
	serverPublicKey = sliceToArray32(serverPubKeyB)
	return
}

func encryptMessage(message string, serverPublicKey, clientPrivateKey *[32]byte) (string, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", err
	}
	encrypted := box.Seal([]byte{}, []byte(message), &nonce, serverPublicKey, clientPrivateKey)
	encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce[:])
	msgLen := len(message)
	encryptedMsg := fmt.Sprintf("%d:%s:%s", msgLen, nonceBase64, encryptedBase64)
	return encryptedMsg, nil
}

func decryptMessage(message string, serverPublicKey, clientPrivateKey *[32]byte) (decrypted string, err error) {
	split := strings.Split(message, ":")
	nonce, err := base64.StdEncoding.DecodeString(split[1])
	if err != nil {
		return
	}
	encryptedRes, err := base64.StdEncoding.DecodeString(split[2])
	if err != nil {
		return
	}
	res, ok := box.Open([]byte{}, encryptedRes, sliceToArray24(nonce), serverPublicKey, clientPrivateKey)
	decrypted = string(res)
	if !ok {
		err = fmt.Errorf("Decryption error")
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

func decodeBytes(src []byte) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(out, src)
	return out[:n], err
}

func isJSON(s string) bool {
	var js map[string]interface{}
	return json.Unmarshal([]byte(s), &js) == nil
}
