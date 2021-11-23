package liboidcagent

import "fmt"

// OIDCAgentError is an error type used for returning errors
type OIDCAgentError struct {
	err    string
	help   string
	remote bool
}

func (e OIDCAgentError) Error() string {
	rem := ""
	if e.remote {
		rem = "(remote) "
	}
	return fmt.Sprintf("oidc-agent %serror: %s", rem, e.err)
}

// Help returns a help message if available. This help message helps the user to
// solve the problem. If a help message is available it SHOULD be displayed to
// the user. One can use ErrorWithHelp to obtain both.
func (e OIDCAgentError) Help() string {
	return e.help
}

// ErrorWithHelp returns a string combining the error message and the help
// message (if available).
func (e OIDCAgentError) ErrorWithHelp() string {
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
