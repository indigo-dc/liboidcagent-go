package liboidcagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

type TokenResponse struct {
	Token      string
	Issuer     string
	Expires_At time.Time
}

type tmp_TokenResponse struct {
	Token      string `json:"access_token"`
	Issuer     string `json:"issuer"`
	Expires_At int64  `json:"expires_at"`
}

func GetAccessToken(accountname string, min_valid_period uint64, scope string, application_hint string) (token string, err error) {
	tokenResponse, err := GetTokenResponse(accountname, min_valid_period, scope, application_hint)
	return tokenResponse.Token, err
}

func GetTokenResponse(accountname string, min_valid_period uint64, scope string, application_hint string) (tokenResponse TokenResponse, e error) {
	socketValue, socketSet := os.LookupEnv("OIDC_SOCK")
	if !socketSet {
		fmt.Fprintln(os.Stderr, "$OIDC_SOCK not set")
		return tokenResponse, errors.New("$OIDC_SOCK not set")
	}

	c, err := net.Dial("unix", socketValue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not connect to socket %s: %s\n", socketValue, err.Error())
		return tokenResponse, err
	}
	defer c.Close()

	ipcReq := fmt.Sprintf(`{"request":"access_token","account":"%s","min_valid_period":%d,"scope":"%s","application_hint":"%s"}`, accountname, min_valid_period, scope, application_hint)
	_, err = c.Write([]byte(ipcReq))
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not write to socket %s: %s\n", socketValue, err.Error())
		return tokenResponse, err
	}
	var response = [4096]byte{}
	length, err := c.Read(response[0:4095])
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not read from socket %s: %s\n", socketValue, err.Error())
		return tokenResponse, err
	}

	response[length] = 0
	var res tmp_TokenResponse
	jsonErr := json.Unmarshal(response[0:length], &res)
	if jsonErr != nil {
		fmt.Fprintf(os.Stderr, "error parsing the response from oidc-agent: %s\n", jsonErr)
		return tokenResponse, jsonErr
	}
	tokenResponse.Token = res.Token
	tokenResponse.Issuer = res.Issuer
	tokenResponse.Expires_At = time.Unix(res.Expires_At, 0)
	return tokenResponse, err
}
