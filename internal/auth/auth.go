package auth

func Authentication(token string) bool {
	return true
}

func Authorization(token, table, column string) bool {
	return true
}
