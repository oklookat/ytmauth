package ytmauth

import (
	"context"
	"errors"
	"time"

	"github.com/oklookat/vantuz"
	"golang.org/x/oauth2"
)

var (
	ErrNilCodes        = errors.New(_errPrefix + "nil codes")
	ErrInvalidGrant    = errors.New(_errPrefix + "incorrect or expired confirmation code")
	ErrBrokenTokensErr = errors.New(_errPrefix + "statusCode != 200, but tokensError is empty (API changed?)")
	ErrBrokenClient    = errors.New(_errPrefix + "broken client_id or client_secret (OAuth App changed?)")
)

const (
	_errAuthorizationPending = "authorization_pending"
	_errInvalidClient        = "invalid_client"
	_errInvalidGrant         = "invalid_grant"
)

type (
	tokensError struct {
		Error string `json:"error"`
	}
)

func requestTokens(ctx context.Context, codes *confirmationCodesResponse) (*oauth2.Token, error) {
	if codes == nil {
		return nil, ErrNilCodes
	}

	form := map[string]string{
		"grant_type":    GrantTypeUrl,
		"code":          codes.DeviceCode,
		"client_id":     ClientId,
		"client_secret": ClientSecret,
	}

	tokensErr := &tokensError{}

	response := &tokensResponse{}
	request := vantuz.C().R().
		SetFormUrlMap(form).
		SetResult(response).SetError(tokensErr)

	expiredDur := time.Duration(codes.ExpiresIn-4) * time.Second
	ctx, cancel := context.WithTimeout(ctx, expiredDur)
	defer cancel()

	sleepFor := time.Duration(codes.Interval+2) * time.Second
	requestSleep := time.NewTicker(sleepFor)
	defer requestSleep.Stop()

	for {
		select {
		// Cancelled.
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-requestSleep.C:
			resp, err := request.Post(ctx, TokenUrl)
			if err != nil {
				return nil, err
			}

			if resp.IsSuccess() {
				result := newOAuthToken(*response)
				return &result, err
			}

			if len(tokensErr.Error) < 1 {
				// ???
				return nil, ErrBrokenTokensErr
			}

			switch tokensErr.Error {
			default:
				return nil, wrapErrStr(tokensErr.Error)
			case _errAuthorizationPending:
				continue
			case _errInvalidClient:
				return nil, ErrBrokenClient
			case _errInvalidGrant:
				return nil, ErrInvalidGrant
			}
		}
	}
}

type tokensResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	RefreshAfter int64  `json:"refresh_after"`
}

func newOAuthToken(from tokensResponse) oauth2.Token {
	return oauth2.Token{
		AccessToken:  from.AccessToken,
		TokenType:    from.TokenType,
		RefreshToken: from.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(from.ExpiresIn) * time.Second),
	}
}
