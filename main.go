package ytmauth

import (
	"context"
	"errors"

	"github.com/oklookat/vantuz"
	"golang.org/x/oauth2"
)

const (
	_errPrefix = "ytmauth: "
)

var (
	ErrNilOnUrlCode = errors.New(_errPrefix + "nil onUrlCode")
	ClientId        = "861556708454-d6dlm3lh05idd8npek18k6be8ba3oc68.apps.googleusercontent.com"
	ClientSecret    = "SboVhoG9s0rNafixCSGGKXAT"
	ScopeUrl        = "https://www.googleapis.com/auth/youtube"
	CodeUrl         = "https://www.youtube.com/o/oauth2/device/code"
	TokenUrl        = "https://oauth2.googleapis.com/token"
	GrantTypeUrl    = "http://oauth.net/grant_type/device/1.0"
)

// onUrlCode - go to Google auth, login into account, and type code.
// After some seconds, you will get token.
//
// Token expires after ~1 day. Use Refresh().
func New(ctx context.Context, onUrlCode func(url string, code string)) (*oauth2.Token, error) {
	if onUrlCode == nil {
		return nil, ErrNilOnUrlCode
	}

	codes, err := getConfirmationCodes(ctx)
	if err != nil {
		return nil, err
	}

	go onUrlCode(codes.VerificationUrl, codes.UserCode)

	return requestTokens(ctx, codes)
}

// Refresh access token.
func Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	form := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     ClientId,
		"client_secret": ClientSecret,
	}

	refreshed := &tokensResponse{}
	tokenErr := &tokensError{}
	request := vantuz.C().R().
		SetFormUrlMap(form).
		SetResult(refreshed).SetError(tokenErr)

	resp, err := request.Post(ctx, TokenUrl)
	if err != nil {
		return nil, err
	}

	if resp.IsError() {
		return nil, wrapErrStr(tokenErr.Error)
	}

	result := newOAuthToken(*refreshed)
	result.RefreshToken = refreshToken

	return &result, err
}
