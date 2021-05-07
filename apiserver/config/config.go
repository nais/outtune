package config

import (
	"github.com/dgrijalva/jwt-go"
)

type Config struct {
	Azure                         Azure
	TokenValidator                jwt.Keyfunc
}

type Azure struct {
	ClientID     string
	DiscoveryURL string
	ClientSecret string
	TenantId     string
}


