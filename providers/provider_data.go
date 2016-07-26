package providers

import (
	"crypto/rsa"
	"net/url"
)

type ProviderData struct {
	ProviderName         string
	ClientID             string
	ClientSecret         string
	LoginURL             *url.URL
	RedeemURL            *url.URL
	ProfileURL           *url.URL
	ProtectedResource    *url.URL
	ValidateURL          *url.URL
	Scope                string
	ApprovalPrompt       string
	CloudfrontKey        *rsa.PrivateKey
	CloudfrontKeyID      string
	CloudfrontBaseDomain string
}

func (p *ProviderData) Data() *ProviderData { return p }
