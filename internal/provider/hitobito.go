package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// Hitobito provider
type Hitobito struct {
	HitobitoDomain       string `long:"domain" env:"HITOBITO_DOMAIN" description:"Domain of the Hitobito instance"`
	HitobitoClientID     string `long:"client-id" env:"HITOBITO_CLIENT_ID" description:"Client ID"`
	HitobitoClientSecret string `long:"client-secret" env:"HITOBITO_CLIENT_SECRET" description:"Client Secret" json:"-"`

	OAuthProvider
}

// Name returns the name of the provider
func (o *Hitobito) Name() string {
	return "hitobito-oauth"
}

// Setup performs validation and setup
func (o *Hitobito) Setup() error {
	// Check parmas
	if o.HitobitoClientID == "" || o.HitobitoClientSecret == "" || o.HitobitoDomain == "" {
		return errors.New("providers.hitobito.hitobito-domain, providers.hitobito.hitobito-client-id, providers.hitobito.hitobito-client-secret must be set")
	}

	// Create oauth2 config
	o.Config = &oauth2.Config{
		ClientID:     o.HitobitoClientID,
		ClientSecret: o.HitobitoClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  o.HitobitoDomain + "/oauth/authorize",
			TokenURL: o.HitobitoDomain + "/oauth/token",
		},
		Scopes: []string{"with_roles"},
	}

	o.ctx = context.Background()

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o *Hitobito) GetLoginURL(redirectURI, state string) string {
	return o.OAuthGetLoginURL(redirectURI, state)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o *Hitobito) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := o.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

// GetUser uses the given token and returns a complete provider.User object
func (o *Hitobito) GetUser(token string) (User, error) {
	var user User

	req, err := http.NewRequest("GET", o.HitobitoDomain+"/oauth/profile", nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("X-Scope", "with_roles")

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return user, err
	}

	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&user)
	fmt.Println(res.Body)

	return user, err
}
