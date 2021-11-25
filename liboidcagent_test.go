package liboidcagent

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAccessToken(t *testing.T) {
	t.Run("shortname", func(t *testing.T) {
		account := os.Getenv("OIDC_AGENT_ACCOUNT")
		if account == "" {
			t.SkipNow()
		}
		req := TokenRequest{
			ShortName: account,
		}
		at, err := GetAccessToken(req)
		assert.Nil(t, err)
		assert.NotZero(t, at)
	})
	t.Run("issuer", func(t *testing.T) {
		issuer := os.Getenv("OIDC_AGENT_ISSUER")
		if issuer == "" {
			t.SkipNow()
		}
		req := TokenRequest{
			IssuerURL: issuer,
		}
		at, err := GetAccessToken(req)
		assert.Nil(t, err)
		assert.NotZero(t, at)
	})
}

func TestGetLoadedAccounts(t *testing.T) {
	accounts, err := GetLoadedAccounts()
	t.Log(accounts)
	assert.Nil(t, err)
	assert.True(t, len(accounts) > 0)
}

func TestGetConfiguredAccounts(t *testing.T) {
	accounts := GetConfiguredAccounts()
	t.Log(accounts)
	assert.True(t, len(accounts) > 0)
}
