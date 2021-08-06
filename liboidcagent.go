package liboidcagent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// OIDCAgentError is an error type used for returning errors
type OIDCAgentError struct {
	err    string
	help   string
	remote bool
}

func (e *OIDCAgentError) Error() string {
	rem := ""
	if e.remote {
		rem = "(remote) "
	}
	return fmt.Sprintf("oidc-agent %serror: %s", rem, e.err)
}

// Help returns a help message if available. This help message helps the user to
// solve the problem. If a help message is available it SHOULD be displayed to
// the user. One can use ErrorWithHelp to obtain both.
func (e *OIDCAgentError) Help() string {
	return e.help
}

// ErrorWithHelp returns a string combining the error message and the help
// message (if available).
func (e *OIDCAgentError) ErrorWithHelp() string {
	help := e.Help()
	err := e.Error()
	if help != "" {
		return fmt.Sprintf("%s\n%s", err, help)
	}
	return err
}

func oidcAgentErrorWrap(err error) error {
	if err == nil {
		return nil
	}
	return &OIDCAgentError{
		err: err.Error(),
	}
}

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
	// The account short name that should be used (Can be omitted if IssuerURL is
	// specified)
	ShortName string
	// The IssuerURL for which an access token should be obtained (Can be omitted
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

func createTokenRequest(req TokenRequest) (string, error) {
	request := tokenRequest{
		Request:         "access_token",
		AccountName:     req.ShortName,
		Issuer:          req.IssuerURL,
		Scope:           strings.Join(req.Scopes, " "),
		Audience:        strings.Join(req.Audiences, " "),
		ApplicationHint: req.ApplicationHint,
		MinValidPeriod:  req.MinValidPeriod,
	}
	r, err := json.Marshal(request)
	return string(r), err
}

func parseIpcResponse(remote bool, response []byte) (res TokenResponse, err error) {
	var rawResponse tokenResponse
	if err = json.Unmarshal(response, &rawResponse); err != nil {
		err = oidcAgentErrorWrap(fmt.Errorf("unable to unmarshal: %s", response))
		return
	}
	if rawResponse.Error != "" {
		err = &OIDCAgentError{
			err:    rawResponse.Error,
			help:   rawResponse.Help,
			remote: remote,
		}
		return
	}
	if rawResponse.Status == "failure" {
		err = &OIDCAgentError{
			err:    "unknown error",
			remote: remote,
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

// GetTokenResponse gets a token response
func GetTokenResponse(req TokenRequest) (resp TokenResponse, err error) {
	if req.ShortName == "" && req.IssuerURL == "" {
		err = &OIDCAgentError{err: "'Shortname' and 'IssuerURL' both not provided"}
		return
	}
	ipcReq, err := createTokenRequest(req)
	if err != nil {
		err = oidcAgentErrorWrap(fmt.Errorf("cannot create agent request: %s", err))
		return
	}
	ipcResponse, err := communicateEncrypted(false, ipcReq)
	if err != nil {
		err = oidcAgentErrorWrap(err)
		if strings.Contains(err.Error(), "$OIDC_SOCK not set") {
			return
		}
		ipcResponse, err = communicateEncrypted(true, ipcReq)
		if err != nil {
			err = oidcAgentErrorWrap(fmt.Errorf("$OIDC_SOCK not set and %s on remote", err))
			return
		}
		resp, err = parseIpcResponse(true, []byte(ipcResponse))
		return
	}
	resp, err = parseIpcResponse(false, []byte(ipcResponse))
	if err != nil && strings.Contains(err.Error(), "No account configured with that short name") {
		localErr := err
		// Try remote
		ipcResponse, err = communicateEncrypted(true, ipcReq)
		if err != nil {
			if strings.Contains(err.Error(), "$OIDC_REMOTE_SOCK not set") {
				err = localErr
			}
			return
		}
		resp, err = parseIpcResponse(true, []byte(ipcResponse))
	}
	return
}

// GetAccessToken gets an access token
func GetAccessToken(req TokenRequest) (string, error) {
	res, err := GetTokenResponse(req)
	return res.Token, err
}
