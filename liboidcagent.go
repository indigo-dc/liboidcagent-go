package liboidcagent

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/adrg/xdg"
)

// TokenResponse is a parsed response from the oidc-agent
type TokenResponse struct {
	// The access token
	Token string
	// The provider that issued the token
	Issuer string
	// The time when the token expires
	ExpiresAt time.Time
}

// TokenRequest is used to request an access token from the agent
type TokenRequest struct {
	// ShortName that should be used (Can be omitted if IssuerURL is specified)
	ShortName string
	// IssuerURL for which an access token should be obtained (Can be omitted
	// if ShortName is specified)
	IssuerURL string
	// MinValidPeriod specifies how long the access token should be valid at
	// least. The time is given in seconds. Default is 0.
	MinValidPeriod uint64
	// The scopes for the requested access token
	Scopes []string
	// The audiences for the requested access token
	Audiences []string
	// A string describing the requesting application (i.e. its name). It might
	// be displayed to the user, if the request must be confirmed or an account
	// configuration loaded.
	ApplicationHint string
}

type tokenResponse struct {
	Token     string `json:"access_token"`
	Issuer    string `json:"issuer"`
	ExpiresAt int64  `json:"expires_at"`

	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
	Help   string `json:"info,omitempty"`
}

type tokenRequest struct {
	Request         string `json:"request"`
	AccountName     string `json:"account,omitempty"`
	Issuer          string `json:"issuer,omitempty"`
	Scope           string `json:"scope,omitempty"`
	Audience        string `json:"audience,omitempty"`
	ApplicationHint string `json:"application_hint,omitempty"`
	MinValidPeriod  uint64 `json:"min_valid_period"`
}

func (c *agentConnection) parseTokenResponse(rawResponse tokenResponse) (res TokenResponse, err error) {
	if rawResponse.Error != "" {
		err = OIDCAgentError{
			err:    rawResponse.Error,
			help:   rawResponse.Help,
			remote: c.Socket.Remote,
		}
		return
	}
	if rawResponse.Status == "failure" {
		err = OIDCAgentError{
			err:    "unknown error",
			remote: c.Socket.Remote,
		}
		return
	}
	res = TokenResponse{
		Token:     rawResponse.Token,
		Issuer:    rawResponse.Issuer,
		ExpiresAt: time.Unix(rawResponse.ExpiresAt, 0),
	}
	return
}

// GetTokenResponse gets a TokenResponse
func GetTokenResponse(req TokenRequest) (resp TokenResponse, err error) {
	if req.ShortName == "" && req.IssuerURL == "" {
		err = OIDCAgentError{err: "'Shortname' and 'IssuerURL' both not provided"}
		return
	}
	conn, err := newEncryptedConn()
	if err != nil {
		return
	}
	defer conn.close()

	rawReq := tokenRequest{
		Request:         "access_token",
		AccountName:     req.ShortName,
		Issuer:          req.IssuerURL,
		Scope:           strings.Join(req.Scopes, " "),
		Audience:        strings.Join(req.Audiences, " "),
		ApplicationHint: req.ApplicationHint,
		MinValidPeriod:  req.MinValidPeriod,
	}
	var rawResp tokenResponse
	err = conn.sendJSONRequest(rawReq, &rawResp)
	if err != nil {
		return
	}

	resp, err = conn.parseTokenResponse(rawResp)
	return
}

// GetAccessToken gets an access token
func GetAccessToken(req TokenRequest) (string, error) {
	res, err := GetTokenResponse(req)
	return res.Token, err
}

func getLoadedAccounts() (accountNames []string, err error) {
	conn, err := newEncryptedConn()
	if err != nil {
		return
	}
	defer conn.close()

	req := map[string]string{"request": "loaded_accounts"}
	var resp struct {
		Status   string   `json:"status"`
		Error    string   `json:"error,omitempty"`
		Accounts []string `json:"info,omitempty"`
	}

	err = conn.sendJSONRequest(req, &resp)
	if err != nil {
		return
	}

	if resp.Status == "success" {
		accountNames = resp.Accounts
		return
	}
	err = fmt.Errorf("error on account request (status: %s): %s", resp.Status, resp.Error)
	return
}

// GetLoadedAccounts returns a list of all accounts which are currently loaded by oidc-agent
func GetLoadedAccounts() (accountNames []string, err error) {
	accountNames, err = getLoadedAccounts()
	if err != nil {
		err = oidcAgentErrorWrap(err)
	}
	return
}

// GetConfiguredAccounts returns a list of all accounts which are configured for oidc-agent
func GetConfiguredAccounts() (accounts []string) {
	accounts = []string{}
	infos, err := ioutil.ReadDir(xdg.ConfigHome + "/oidc-agent")
	if err != nil {
		return
	}
	for _, info := range infos {
		if info.Name() != "issuer.config" && !info.IsDir() {
			accounts = append(accounts, info.Name())
		}
	}
	return accounts
}
