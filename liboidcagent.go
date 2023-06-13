package liboidcagent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	mytoken "github.com/oidc-mytoken/api/v0"
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

// MytokenResponse is a parse response from the oidc-agent compatible with the struct from the mytoken api,
// but with ExpiresAt set instead of ExpiresIn
type MytokenResponse struct {
	mytoken.MytokenResponse
	OIDCIssuer    string
	MytokenIssuer string
	// The time when the token expires
	ExpiresAt time.Time
}

// AccountInfoResponse holds information about the available accounts and issuers
type AccountInfoResponse map[string]IssuerInfo

// IssuerInfo is a type for holding information about a supported issuer
type IssuerInfo struct {
	// Indicates whether a public client for this issuer is available or not
	HasPubClient bool `json:"pubclient"`
	// Maps account short names to a bool indicating if this account is currently loaded or not
	Accounts map[string]bool `json:"accounts"`
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

// MytokenRequest is used to request a  mytoken from the agent
type MytokenRequest struct {
	// ShortName that should be used
	ShortName string
	// A mytoken profile describing the properties of the requested mytoken
	MytokenProfile string
	// A string describing the requesting application (i.e. its name). It might
	// be displayed to the user, if the request must be confirmed or an account
	// configuration loaded.
	ApplicationHint string
}

type tokenResponse struct {
	Token     string `json:"access_token"`
	Issuer    string `json:"issuer"`
	ExpiresAt int64  `json:"expires_at"`

	mytoken.MytokenResponse
	OIDCIssuer    string `json:"oidc_issuer"`
	MytokenIssuer string `json:"mytoken_issuer"`

	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
	Help   string `json:"info,omitempty"`
}

type infoResponse struct {
	Info json.RawMessage `json:"info"`

	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

type tokenRequest struct {
	Request         string `json:"request"`
	AccountName     string `json:"account,omitempty"`
	Issuer          string `json:"issuer,omitempty"`
	Scope           string `json:"scope,omitempty"`
	Audience        string `json:"audience,omitempty"`
	ApplicationHint string `json:"application_hint,omitempty"`
	MinValidPeriod  uint64 `json:"min_valid_period"`
	MytokenProfile  string `json:"mytoken_profile"`
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

func (c *agentConnection) parseMytokenResponse(rawResponse tokenResponse) (res MytokenResponse, err error) {
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
	res = MytokenResponse{
		MytokenResponse: rawResponse.MytokenResponse,
		OIDCIssuer:      rawResponse.OIDCIssuer,
		MytokenIssuer:   rawResponse.MytokenIssuer,
		ExpiresAt:       time.Unix(rawResponse.ExpiresAt, 0),
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

// GetMytokenResponse gets a mytoken response from the agent
func GetMytokenResponse(req MytokenRequest) (resp MytokenResponse, err error) {
	if req.ShortName == "" {
		err = OIDCAgentError{err: "'Shortname' not provided"}
		return
	}
	conn, err := newEncryptedConn()
	if err != nil {
		return
	}
	defer conn.close()

	rawReq := tokenRequest{
		Request:         "mytoken",
		AccountName:     req.ShortName,
		MytokenProfile:  req.MytokenProfile,
		ApplicationHint: req.ApplicationHint,
	}
	var rawResp tokenResponse
	err = conn.sendJSONRequest(rawReq, &rawResp)
	if err != nil {
		return
	}

	resp, err = conn.parseMytokenResponse(rawResp)
	return
}

// GetMytoken gets an mytoken
func GetMytoken(req MytokenRequest) (string, error) {
	res, err := GetMytokenResponse(req)
	return res.Mytoken, err
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
func GetConfiguredAccounts() (accounts []string, err error) {
	accountInfo, err := GetAccountInfos()
	if err != nil {
		return nil, err
	}
	for _, i := range accountInfo {
		for a := range i.Accounts {
			accounts = append(accounts, a)
		}
	}
	return
}

func getAccountInfos() (accountInfos AccountInfoResponse, err error) {
	conn, err := newEncryptedConn()
	if err != nil {
		return
	}
	defer conn.close()

	req := map[string]string{"request": "account_info"}
	var resp infoResponse

	err = conn.sendJSONRequest(req, &resp)
	if err != nil {
		return
	}

	if resp.Status != "success" {
		err = fmt.Errorf("error on account info request (status: %s): %s", resp.Status, resp.Error)
		return
	}
	err = json.Unmarshal(resp.Info, &accountInfos)
	if err != nil {
		err = fmt.Errorf("error on account info request: account info malformed: %s", err.Error())
		return
	}
	return
}

// GetAccountInfos returns information about all issuers and their available account names and if those are loaded or
// not
func GetAccountInfos() (info AccountInfoResponse, err error) {
	info, err = getAccountInfos()
	if err != nil {
		err = oidcAgentErrorWrap(err)
	}
	return
}
