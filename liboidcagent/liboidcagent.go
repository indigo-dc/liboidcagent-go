package liboidcagent

func GetAccessToken(accountname string, min_valid_period uint64, scope string, application_hint string) (err bool, token string) {
	err = false
	token = ""
	return err, token
}
