package main

import (
	"fmt"
	"github.com/arglucas/totp/pkg/totp"
)

// TODO: Eventually convert this to more of a CLI tool with options. Move this to an example.
func main() {

	key := []byte("12345678901234567890")

	//fmt.Println(time.Now().Unix())     // seconds since 1970

	code, _ := totp.TOTP(key, 59, 30, 8, totp.SHA1)
	fmt.Println("TOTP Code: ", code)
}

