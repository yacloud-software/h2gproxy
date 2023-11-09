package srv

import (
	"fmt"
	apb "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/go-easyops/common"
	"golang.conradwood.net/go-easyops/utils"
	"golang.yacloud.eu/apis/sessionmanager"
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

// if token is invalid - returns nil,nil
// if something goes wrong resolving token, returns nil,error
// if token resolves to a valid and authenticated user, returns user,nil

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
	var user_result *apb.SignedUser
	var gdr *apb.SignedAuthResponse

	// check the session manager
	st := &sessionmanager.SessionToken{Token: token}
	ctx := createBootstrapContext()
	sv, err := sessionmanager.GetSessionManagerClient().VerifySession(ctx, st)
	if err != nil {
		fmt.Printf("WARNING - session manager failure: %s\n", utils.ErrorString(err))
		// we do not return an error here, we give the authserver a chance to handle it
		// long-term, it should not. this code needs to prove its reliability first though
	}
	if sv != nil && sv.IsSessionToken {
		// a valid session token detected
		if !sv.IsValid {
			// valid session, but no user with session
			return nil, nil
		}
		user_result = sv.User

		goto got_user
	}
	// check the auth-server

	// do the "real" lookup
	ctx = createBootstrapContext()
	gdr, err = AuthServer.SignedGetByToken(ctx, &apb.AuthenticateTokenRequest{Token: token})
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
	user_result = gdr.User
got_user:
	uu := common.VerifySignedUser(user_result)
	if uu == nil {
		panic("signature invalid")
	}
	if !uu.Active {
		cache_PutUser(token, user_result, fmt.Errorf("Useraccount deactivated"))
		return nil, fmt.Errorf("Useraccount deactivated")
	}
	cache_PutUser(token, user_result, nil)
	return user_result, nil
}
