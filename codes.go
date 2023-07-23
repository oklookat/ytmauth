package ytmauth

import (
	"context"

	"github.com/oklookat/vantuz"
)

func getConfirmationCodes(ctx context.Context) (*confirmationCodesResponse, error) {
	form := map[string]string{}
	form["scope"] = ScopeUrl
	form["client_id"] = ClientId

	codes := &confirmationCodesResponse{}
	respErr := &tokensError{}

	request := vantuz.C().R().
		SetFormUrlMap(form).
		SetResult(&codes).
		SetError(respErr)

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	resp, err := request.Post(ctx, CodeUrl)
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		err = wrapErrStr(respErr.Error)
	}

	return codes, err
}

type (
	confirmationCodesResponse struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationUrl string `json:"verification_url"`
		Interval        int    `json:"interval"`
		ExpiresIn       int    `json:"expires_in"`
	}
)
