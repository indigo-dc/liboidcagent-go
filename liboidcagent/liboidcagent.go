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

// TokenResponse is a parsed response from the oidc-agent
type TokenResponse struct {
	Token     string
	Issuer    string
	ExpiresAt time.Time
}

type rawTokenResponse struct {
	Token     string `json:"access_token"`
	Issuer    string `json:"issuer"`
	ExpiresAt int64  `json:"expires_at"`

	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

func createTokenRequest(requestPartAccIss string, minValidPeriod uint64, scope string, applicationHint string) string {
	requestPartScope := ""
	if scope != "" {
		requestPartScope = fmt.Sprintf(`,"scope":"%s"`, scope)
	}
	requestPartApplicationHint := ""
	if applicationHint != "" {
		requestPartApplicationHint = fmt.Sprintf(`,"application_hint":"%s"`, applicationHint)
	}
	return fmt.Sprintf(`{"request":"access_token"%s,"min_valid_period":%d%s%s}`, requestPartAccIss, minValidPeriod, requestPartScope, requestPartApplicationHint)
}

func createTokenRequestAccount(accountname string, minValidPeriod uint64, scope string, applicationHint string) string {
	requestPartAcc := fmt.Sprintf(`,"account":"%s"`, accountname)
	return createTokenRequest(requestPartAcc, minValidPeriod, scope, applicationHint)
}

func createTokenRequestIssuer(issuer string, minValidPeriod uint64, scope string, applicationHint string) string {
	requestPartIss := fmt.Sprintf(`,"issuer":"%s"`, issuer)
	return createTokenRequest(requestPartIss, minValidPeriod, scope, applicationHint)
}

func communicateWithSock(request string) (response []byte, err error) {
	socketValue, socketSet := os.LookupEnv("OIDC_SOCK")
	if !socketSet {
		err = errors.New("$OIDC_SOCK not set")
		return
	}

	c, err := net.Dial("unix", socketValue)
	if err != nil {
		err = fmt.Errorf("Dialing socket: %s", err)
		return
	}
	defer c.Close()

	_, err = c.Write([]byte(request))
	if err != nil {
		err = fmt.Errorf("Writing to socket: %s", err)
		return
	}
	response, err = ioutil.ReadAll(c)
	if err != nil {
		err = fmt.Errorf("Reading from socket: %s", err)
	}
	return
}

func parseIpcResponse(response []byte) (tokenResponse TokenResponse, err error) {
	var res rawTokenResponse
	err = json.Unmarshal(response, &res)
	if err != nil {
		err = fmt.Errorf("Unable to unmarshal: %s", response)
		return
	}
	if res.Error != "" {
		err = fmt.Errorf("Agent error: %s", res.Error)
		return
	}
	if res.Status == "failure" {
		err = fmt.Errorf("status is \"failure\"")
		return
	}
	tokenResponse = TokenResponse{
		Token:     res.Token,
		Issuer:    res.Issuer,
		ExpiresAt: time.Unix(res.ExpiresAt, 0),
	}
	return
}

// GetTokenResponse gets a token response by accountname
func GetTokenResponse(accountname string, minValidPeriod uint64, scope, applicationHint string) (resp TokenResponse, err error) {
	ipcReq := createTokenRequestAccount(accountname, minValidPeriod, scope, applicationHint)
	ipcResponse, err := communicateWithSock(ipcReq)
	if err != nil {
		return
	}
	resp, err = parseIpcResponse(ipcResponse)
	return
}

// GetTokenResponseByIssuerURL gets a token response by issuerURL
func GetTokenResponseByIssuerURL(issuer string, minValidPeriod uint64, scope, applicationHint string) (tokenResponse TokenResponse, err error) {
	ipcReq := createTokenRequestIssuer(issuer, minValidPeriod, scope, applicationHint)
	response, err := communicateWithSock(ipcReq)
	if err != nil {
		err = fmt.Errorf("Communicating with socket: %s", err)
		return
	}
	tokenResponse, err = parseIpcResponse(response)
	return
}

// GetAccessToken gets an access token by accountname
func GetAccessToken(accountname string, minValidPeriod uint64, scope, applicationHint string) (token string, err error) {
	tokenResponse, err := GetTokenResponse(accountname, minValidPeriod, scope, applicationHint)
	return tokenResponse.Token, err
}

// GetAccessTokenByIssuerURL gets an access token by issuerURL
func GetAccessTokenByIssuerURL(issuerURL string, minValidPeriod uint64, scope, applicationHint string) (token string, err error) {
	tokenResponse, err := GetTokenResponseByIssuerURL(issuerURL, minValidPeriod, scope, applicationHint)
	return tokenResponse.Token, err
}
