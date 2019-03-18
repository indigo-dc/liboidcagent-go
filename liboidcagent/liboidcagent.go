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

func GetAccessTokenByIssuerUrl(issuer_url string, min_valid_period uint64, scope string, application_hint string) (token string, err error) {
	tokenResponse, err := GetTokenResponseByIssuerUrl(issuer_url, min_valid_period, scope, application_hint)
	return tokenResponse.Token, err
}

func communicateWithSock(request string) (response []byte, e error) {
	socketValue, socketSet := os.LookupEnv("OIDC_SOCK")
	if !socketSet {
		fmt.Fprintln(os.Stderr, "$OIDC_SOCK not set")
		return response, errors.New("$OIDC_SOCK not set")
	}

	c, err := net.Dial("unix", socketValue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not connect to socket %s: %s\n", socketValue, err.Error())
		return response, err
	}
	defer c.Close()

	_, err = c.Write([]byte(request))
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not write to socket %s: %s\n", socketValue, err.Error())
		return response, err
	}
	var res = [4096]byte{}
	length, err := c.Read(res[0:4095])
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not read from socket %s: %s\n", socketValue, err.Error())
		return response, err
	}
	res[length] = 0
	return res[:length], nil
}

//TODO error handling
func GetTokenResponse(accountname string, min_valid_period uint64, scope string, application_hint string) (tokenResponse TokenResponse, e error) {

	//TODO scope and application hint only needed if not empty
	ipcReq := fmt.Sprintf(`{"request":"access_token","account":"%s","min_valid_period":%d,"scope":"%s","application_hint":"%s"}`, accountname, min_valid_period, scope, application_hint)

	response, err := communicateWithSock(ipcReq)
	if err != nil {
		return tokenResponse, err
	}

	var res tmp_TokenResponse
	jsonErr := json.Unmarshal(response, &res)
	if jsonErr != nil {
		fmt.Fprintf(os.Stderr, "error parsing the response from oidc-agent: %s\n", jsonErr)
		return tokenResponse, jsonErr
	}
	tokenResponse.Token = res.Token
	tokenResponse.Issuer = res.Issuer
	tokenResponse.Expires_At = time.Unix(res.Expires_At, 0)
	return tokenResponse, err
}

//TODO error handling
func GetTokenResponseByIssuerUrl(issuer string, min_valid_period uint64, scope string, application_hint string) (tokenResponse TokenResponse, e error) {

	//TODO scope and application hint only needed if not empty
	ipcReq := fmt.Sprintf(`{"request":"access_token","issuer":"%s","min_valid_period":%d,"scope":"%s","application_hint":"%s"}`, issuer, min_valid_period, scope, application_hint)

	response, err := communicateWithSock(ipcReq)
	if err != nil {
		return tokenResponse, err
	}

	var res tmp_TokenResponse
	jsonErr := json.Unmarshal(response, &res)
	if jsonErr != nil {
		fmt.Fprintf(os.Stderr, "error parsing the response from oidc-agent: %s\n", jsonErr)
		return tokenResponse, jsonErr
	}
	tokenResponse.Token = res.Token
	tokenResponse.Issuer = res.Issuer
	tokenResponse.Expires_At = time.Unix(res.Expires_At, 0)
	return tokenResponse, err
}
