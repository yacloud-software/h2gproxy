package srv

import (
	apb "golang.conradwood.net/apis/auth"
	"golang.conradwood.net/go-easyops/cache"
	"time"
)

var (
	authcache *cache.Cache
)

func startAuthCache() {
	authcache = cache.New("h2gproxy_authcache", time.Duration(20)*time.Second, 100)
}

type AuthResponse struct {
	Granted        bool
	SignedAuthUser *apb.SignedUser
	Token          string
	Error          error
}

func (a *AuthResponse) Key() string {
	return a.Token
}

func cache_GetUserByToken(token string) *AuthResponse {
	if authcache == nil {
		return nil
	}
	c := authcache.Get(token)
	if c == nil {
		return nil
	}
	return c.(*AuthResponse)
}

func cache_PutUser(token string, user *apb.SignedUser, err error) {
	if authcache == nil {
		return
	}
	ar := &AuthResponse{Token: token, SignedAuthUser: user, Error: err}
	authcache.Put(ar.Key(), ar)
}
