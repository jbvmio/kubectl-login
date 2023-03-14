package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd/api"
)

const (
	discoveryEndpoint = `/.well-known/openid-configuration`
	grantType         = `urn:ietf:params:oauth:grant-type:device_code`
)

func contextOIDCIssuer(cfg api.Config) (string, error) {
	ext, there := cfg.Extensions[`oidcUrl`]
	if !there {
		return "", fmt.Errorf("error: oidcUrl extension missing")
	}
	var ctxUrls map[string]string
	err := json.Unmarshal(ext.(*runtime.Unknown).Raw, &ctxUrls)
	if err != nil {
		return "", fmt.Errorf("oidcUrl Unmarshal error: %w", err)
	}
	if u, ok := ctxUrls[cfg.CurrentContext]; ok {
		return u, nil
	}
	return ctxUrls[`default`], nil
}

func newAuthConfig(issuerURL string) *api.AuthProviderConfig {
	return &api.AuthProviderConfig{
		Name: `oidc`,
		Config: map[string]string{
			`client-id`:                      `kubectl`,
			`client-secret`:                  "",
			`id-token`:                       "",
			`idp-certificate-authority-data`: "",
			`idp-issuer-url`:                 issuerURL,
			`refresh-token`:                  "",
		},
	}
}

// IssuerURL represents an RFC1738 Compliant HTTP/S URL.
type IssuerURL string

func (i IssuerURL) discover(client *http.Client) (discoveredURLs, error) {
	var d discoveredURLs
	switch {
	case i == "":
		return d, fmt.Errorf("issuer url is empty")
	case !strings.HasPrefix(string(i), "http") || !strings.Contains(string(i), `://`):
		return d, fmt.Errorf("invalid scheme: %s", i)
	}
	resp, err := client.Get(string(i) + discoveryEndpoint)
	if err != nil {
		return d, fmt.Errorf("issuer url discovery error: %w", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return d, fmt.Errorf("discovery response error: %w", err)
	}
	err = json.Unmarshal(body, &d)
	if err != nil {
		return d, fmt.Errorf("oidc discovery is unavailable") //fmt.Errorf("discovery unmarshal error: %w", err)
	}
	s := strings.Split(d.Issuer, `://`)[0]
	b := strings.TrimPrefix(d.Issuer, s+`://`)
	b = strings.Split(b, `/`)[0]
	d.baseURL = s + `://` + b
	if d.baseURL == "" {
		err = fmt.Errorf("error discovering base url")
	}
	return d, err
}

type discoveredURLs struct {
	Issuer         string `json:"issuer"`
	Auth           string `json:"authorization_endpoint"`
	Token          string `json:"token_endpoint"`
	Keys           string `json:"jwks_uri"`
	UserInfo       string `json:"userinfo_endpoint"`
	DeviceEndpoint string `json:"device_authorization_endpoint"`
	baseURL        string
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

func startAuth(authConfig *api.AuthProviderConfig, iURL, user, pass string) error {
	staticRootCA, err := certdecode(base64RootCA)
	if err != nil {
		return err
	}
	client, err := httpClientForRootCAs(staticRootCA)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}
	I, err := IssuerURL(iURL).discover(client)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Add(`client_id`, `kubectl`)
	form.Add(`scope`, `openid profile email offline_access groups`)
	resp, err := client.PostForm(I.DeviceEndpoint, form)
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
	resp, err = client.PostForm(I.Issuer+`/device/auth/verify_code`, form)
	if err != nil {
		return fmt.Errorf("verification init error: %w", err)
	}
	loc := resp.Request.Response.Header.Get(`Location`)
	for k := range form {
		delete(form, k)
	}
	form.Add(`login`, user)
	form.Add(`password`, pass)
	resp, err = client.PostForm(I.baseURL+loc, form)
	if err != nil {
		return fmt.Errorf("login error: %w", err)
	}
	for k := range form {
		delete(form, k)
	}
	form.Add(`device_code`, dcr.DeviceCode)
	form.Add(`grant_type`, grantType)
	resp, err = client.PostForm(I.Token, form)
	if err != nil {
		return fmt.Errorf("login verification error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("invalid username and/or password")
	}
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
	authConfig.Config[`idp-certificate-authority-data`] = base64.StdEncoding.EncodeToString([]byte(staticRootCA))
	return nil
}

// return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(rootCAs string) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	rootCABytes := []byte(rootCAs)
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

func certdecode(v string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", fmt.Errorf("certificate error: %w", err)
	}
	return string(data), nil
}

var base64RootCA string
