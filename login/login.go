package login

var initUsername = "redrock"
var initPassword = "redrock"

func ChangeUsernameAndPassword(changedusername string, changedpassword string) {
	initUsername = changedusername
	initPassword = changedpassword
}

func Login(username, password string) bool {

	if username == initUsername && password == initPassword {
		return true
	}

	return false
}
