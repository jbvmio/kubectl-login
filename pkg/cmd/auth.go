package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"k8s.io/client-go/tools/clientcmd/api"
)

const (
	issuerBaseURL = `http://127.0.0.1:5556`
	issuerSubpath = `/dex`
	issuerURL     = issuerBaseURL + issuerSubpath
	grantType     = `urn:ietf:params:oauth:grant-type:device_code`
)

func newAuthConfig() *api.AuthProviderConfig {
	return &api.AuthProviderConfig{
		Name: `oidc`,
		Config: map[string]string{
			`client-id`:                 `kubectl`,
			`client-secret`:             "",
			`id-token`:                  "",
			`idp-certificate-authority`: `/root/ca.pem`,
			`idp-issuer-url`:            issuerURL,
			`refresh-token`:             "",
		},
	}
}

type deviceCodeResponse struct {
	// The unique device code for device authentication
	DeviceCode string `json:"device_code"`
	// The code the user will exchange via a browser and log in
	UserCode string `json:"user_code"`
	// The url to verify the user code.
	VerificationURI string `json:"verification_uri"`
	// The verification uri with the user code appended for pre-filling form
	VerificationURIComplete string `json:"verification_uri_complete"`
	// The lifetime of the device code
	ExpireTime int `json:"expires_in"`
	// How often the device is allowed to poll to verify that the user login occurred
	PollInterval int `json:"interval"`
}

type oidcToken struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func startAuth(authConfig *api.AuthProviderConfig, user, pass string) error {
	form := url.Values{}
	form.Add(`client_id`, `kubectl`)
	form.Add(`scope`, `openid profile email offline_access groups`)
	resp, err := http.PostForm(issuerURL+`/device/code`, form)
	if err != nil {
		return fmt.Errorf("init login error: %w", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading init response: %w", err)
	}
	var dcr deviceCodeResponse
	err = json.Unmarshal(body, &dcr)
	if err != nil {
		return fmt.Errorf("unmarshal init response error: %w", err)
	}
	for k := range form {
		delete(form, k)
	}
	form.Add(`user_code`, dcr.UserCode)
	resp, err = http.PostForm(issuerURL+`/device/auth/verify_code`, form)
	if err != nil {
		return fmt.Errorf("verification init error: %w", err)
	}
	loc := resp.Request.Response.Header.Get(`Location`)
	for k := range form {
		delete(form, k)
	}
	form.Add(`login`, user)
	form.Add(`password`, pass)
	resp, err = http.PostForm(issuerBaseURL+loc, form)
	if err != nil {
		return fmt.Errorf("login error: %w", err)
	}
	for k := range form {
		delete(form, k)
	}
	form.Add(`device_code`, dcr.DeviceCode)
	form.Add(`grant_type`, grantType)
	resp, err = http.PostForm(issuerURL+`/token`, form)
	if err != nil {
		return fmt.Errorf("login verification error: %w", err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading verification response: %w", err)
	}
	var token oidcToken
	err = json.Unmarshal(body, &token)
	if err != nil {
		return fmt.Errorf("unmarshal token error: %w", err)
	}
	authConfig.Config[`id-token`] = token.IDToken
	authConfig.Config[`refresh-token`] = token.RefreshToken
	fmt.Printf("%+v\n", token)

	return nil
}
