package srv

import (
	"fmt"
	apb "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/go-easyops/common"
	"net/http"
	"sync"
)

var (
	tokenlock sync.Mutex
)

func GetUserFromCookie(c *http.Cookie) *apb.SignedUser {
	if *debug {
		fmt.Printf("Cookie: %v\n", c)
	}
	if c == nil {
		return nil
	}
	tok := c.Value
	user, err := TokenToUser(tok)
	if err != nil {
		fmt.Printf("Error getting user for token %s: %s\n", tok, err)
		return nil
	}
	return user
}

func TokenToUser(token string) (*apb.SignedUser, error) {
	uc := cache_GetUserByToken(token)
	if uc != nil {
		return uc.SignedAuthUser, uc.Error
	}
	// TODO: this should probably be more granular, as in: "per token" or so
	tokenlock.Lock()
	defer tokenlock.Unlock()
	uc = cache_GetUserByToken(token)
	if uc != nil {
		return uc.SignedAuthUser, uc.Error
	}

	// do the "real" lookup
	gdr, err := AuthServer.SignedGetByToken(createBootstrapContext(), &apb.AuthenticateTokenRequest{Token: token})
	if err != nil {
		if *debug {
			fmt.Printf("Error getting user for token %s: %s\n", token, err)
		}
		cache_PutUser(token, nil, err)
		return nil, err
	}
	if !gdr.Valid {
		fmt.Println("Not valid")
		return nil, fmt.Errorf("invalid user")
	}
	user := gdr.User
	uu := common.VerifySignedUser(user)
	if uu == nil {
		panic("signature invalid")
	}
	if !uu.Active {
		cache_PutUser(token, user, fmt.Errorf("Useraccount deactivated"))
		return nil, fmt.Errorf("Useraccount deactivated")
	}
	cache_PutUser(token, user, nil)
	return user, nil
}
