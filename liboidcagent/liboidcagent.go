package liboidcagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
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

func _createTokenRequest(requestPartAccIss string, min_valid_period uint64, scope string, application_hint string) string {
	requestPartScope := ""
	if scope != "" {
		requestPartScope = fmt.Sprintf(`,"scope":"%s"`, scope)
	}
	requestPartApplicationHint := ""
	if application_hint != "" {
		requestPartScope = fmt.Sprintf(`,"application_hint":"%s"`, application_hint)
	}
	return fmt.Sprintf(`{"request":"access_token"%s,"min_valid_period":%d%s%s}`, requestPartAccIss, min_valid_period, requestPartScope, requestPartApplicationHint)
}

func createTokenRequestAccount(accountname string, min_valid_period uint64, scope string, application_hint string) string {
	requestPartAcc := fmt.Sprintf(`,"account":"%s"`, accountname)
	return _createTokenRequest(requestPartAcc, min_valid_period, scope, application_hint)
}

func createTokenRequestIssuer(issuer string, min_valid_period uint64, scope string, application_hint string) string {
	requestPartIss := fmt.Sprintf(`,"issuer":"%s"`, issuer)
	return _createTokenRequest(requestPartIss, min_valid_period, scope, application_hint)
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
	res, err := ioutil.ReadAll(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not read from socket %s: %s\n", socketValue, err.Error())
		return response, err
	}
	return res, nil
}

//TODO error handling
func GetTokenResponse(accountname string, min_valid_period uint64, scope string, application_hint string) (tokenResponse TokenResponse, e error) {
	ipcReq := createTokenRequestAccount(accountname, min_valid_period, scope, application_hint)
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
	ipcReq := createTokenRequestIssuer(issuer, min_valid_period, scope, application_hint)
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
