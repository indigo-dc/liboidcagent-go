package liboidcagent

import (
	"encoding/json"
	"fmt"
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

func createTokenRequest(requestPartAccIss string, minValidPeriod uint64, scope string, applicationHint, audience string) string {
	requestPartScope := ""
	if scope != "" {
		requestPartScope = fmt.Sprintf(`,"scope":"%s"`, scope)
	}
	requestPartApplicationHint := ""
	if applicationHint != "" {
		requestPartApplicationHint = fmt.Sprintf(`,"application_hint":"%s"`, applicationHint)
	}
	requestPartAudience := ""
	if audience != "" {
		requestPartAudience = fmt.Sprintf(`,"audience":"%s"`, audience)
	}
	return fmt.Sprintf(`{"request":"access_token"%s,"min_valid_period":%d%s%s%s}`, requestPartAccIss, minValidPeriod, requestPartScope, requestPartApplicationHint, requestPartAudience)
}

func createTokenRequestAccount(accountname string, minValidPeriod uint64, scope string, applicationHint, audience string) string {
	requestPartAcc := fmt.Sprintf(`,"account":"%s"`, accountname)
	return createTokenRequest(requestPartAcc, minValidPeriod, scope, applicationHint, audience)
}

func createTokenRequestIssuer(issuer string, minValidPeriod uint64, scope string, applicationHint, audience string) string {
	requestPartIss := fmt.Sprintf(`,"issuer":"%s"`, issuer)
	return createTokenRequest(requestPartIss, minValidPeriod, scope, applicationHint, audience)
}

func parseIpcResponse(remote bool, response []byte) (tokenResponse TokenResponse, err error) {
	rem := ""
	if remote {
		rem = "Remote "
	}
	var res rawTokenResponse
	err = json.Unmarshal(response, &res)
	if err != nil {
		err = fmt.Errorf("Unable to unmarshal: %s", response)
		return
	}
	if res.Error != "" {
		err = fmt.Errorf("%sAgent error: %s", rem, res.Error)
		return
	}
	if res.Status == "failure" {
		err = fmt.Errorf("%sstatus is \"failure\"", rem)
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
//
// Deprecated: GetTokenResponse is deprecated and only exists for compatibility
// reasons. New applications should use GetTokenResponse2 instead.
func GetTokenResponse(accountname string, minValidPeriod uint64, scope, applicationHint string) (resp TokenResponse, err error) {
	return GetTokenResponse2(accountname, minValidPeriod, scope, applicationHint, "")
}

// GetTokenResponse2 gets a token response by accountname
func GetTokenResponse2(accountname string, minValidPeriod uint64, scope, applicationHint, audience string) (resp TokenResponse, err error) {
	ipcReq := createTokenRequestAccount(accountname, minValidPeriod, scope, applicationHint, audience)
	ipcResponse, err := communicateEncrypted(false, ipcReq)
	if err != nil {
		if err.Error() != "$OIDC_SOCK not set" {
			return
		}
		ipcResponse, err = communicateEncrypted(true, ipcReq)
		if err != nil {
			err = fmt.Errorf("$OIDC_SOCK not set and %s on remote", err)
			return
		}
		resp, err = parseIpcResponse(true, []byte(ipcResponse))
		return
	}
	resp, err = parseIpcResponse(false, []byte(ipcResponse))
	if err != nil && err.Error() == "Agent error: No account configured with that short name" {
		localErr := err
		//Try remote
		ipcResponse, err = communicateEncrypted(true, ipcReq)
		if err != nil {
			if err.Error() == "$OIDC_REMOTE_SOCK not set" {
				err = localErr
			}
			return
		}
		resp, err = parseIpcResponse(true, []byte(ipcResponse))
	}
	return
}

// GetTokenResponseByIssuerURL gets a token response by issuerURL
//
// Deprecated: GetTokenResponseByIssuerURL is deprecated and only exists for
// compatibility reasons. New applications should use
// GetTokenResponseByIssuerURL2 instead.
func GetTokenResponseByIssuerURL(issuer string, minValidPeriod uint64, scope, applicationHint string) (tokenResponse TokenResponse, err error) {
	return GetTokenResponseByIssuerURL2(issuer, minValidPeriod, scope, applicationHint, "")
}

// GetTokenResponseByIssuerURL2 gets a token response by issuerURL
func GetTokenResponseByIssuerURL2(issuer string, minValidPeriod uint64, scope, applicationHint, audience string) (tokenResponse TokenResponse, err error) {
	ipcReq := createTokenRequestIssuer(issuer, minValidPeriod, scope, applicationHint, audience)
	response, err := communicateEncrypted(false, ipcReq)
	if err != nil {
		err = fmt.Errorf("Communicating with socket: %s", err)
		return
	}
	tokenResponse, err = parseIpcResponse(false, []byte(response))
	return
}

// GetAccessToken gets an access token by accountname
//
// Deprecated: GetAccessToken is deprecated and only exists for compatibility
// reasons. New applications should use GetAccessToken2 instead.
func GetAccessToken(accountname string, minValidPeriod uint64, scope, applicationHint string) (token string, err error) {
	return GetAccessToken2(accountname, minValidPeriod, scope, applicationHint, "")
}

// GetAccessToken2 gets an access token by accountname
func GetAccessToken2(accountname string, minValidPeriod uint64, scope, applicationHint, audience string) (token string, err error) {
	tokenResponse, err := GetTokenResponse2(accountname, minValidPeriod, scope, applicationHint, audience)
	return tokenResponse.Token, err
}

// GetAccessTokenByIssuerURL gets an access token by issuerURL
//
// Deprecated: GetAccessTokenByIssuerURL is deprecated and only exists for compatibility
// reasons. New applications should use GetAccessTokenByIssuerURL2 instead.
func GetAccessTokenByIssuerURL(issuerURL string, minValidPeriod uint64, scope, applicationHint string) (token string, err error) {
	return GetAccessTokenByIssuerURL2(issuerURL, minValidPeriod, scope, applicationHint, "")
}

// GetAccessTokenByIssuerURL2 gets an access token by issuerURL
func GetAccessTokenByIssuerURL2(issuerURL string, minValidPeriod uint64, scope, applicationHint, audience string) (token string, err error) {
	tokenResponse, err := GetTokenResponseByIssuerURL2(issuerURL, minValidPeriod, scope, applicationHint, audience)
	return tokenResponse.Token, err
}
