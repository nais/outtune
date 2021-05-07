package validate

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/nais/outtune/apiserver/azure/discovery"
	"github.com/nais/outtune/apiserver/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	"net/http"
)

func JWTValidator(certificates map[string]discovery.CertificateList, audience string) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		var certificateList discovery.CertificateList
		var kid string
		var ok bool

		if claims, ok := token.Claims.(*jwt.MapClaims); !ok {
			return nil, fmt.Errorf("unable to retrieve claims from token")
		} else {
			if valid := claims.VerifyAudience(audience, true); !valid {
				return nil, fmt.Errorf("the token is not valid for this application")
			}
		}

		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		if kid, ok = token.Header["kid"].(string); !ok {
			return nil, fmt.Errorf("field 'kid' is of invalid type %T, should be string", token.Header["kid"])
		}

		if certificateList, ok = certificates[kid]; !ok {
			return nil, fmt.Errorf("kid '%s' not found in certificate list", kid)
		}

		for _, certificate := range certificateList {
			return certificate.PublicKey, nil
		}

		return nil, fmt.Errorf("no certificate candidates for kid '%s'", kid)
	}
}

func Validator(azureConfig config.Azure, jwtValidator jwt.Keyfunc) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			oauthConfig := oauth2.Config{
				ClientID:     azureConfig.ClientID,
				ClientSecret: azureConfig.ClientSecret,
				Endpoint:     endpoints.AzureAD(azureConfig.TenantId),
				RedirectURL:  r.URL.String(),
				Scopes:       []string{"openid"},
			}
			code := r.URL.Query().Get("code")
			exchange, err := oauthConfig.Exchange(r.Context(), code)
			if err != nil {
				log.Errorf("exchange code for token: %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			var claims jwt.MapClaims
			_, err = jwt.ParseWithClaims(exchange.AccessToken, &claims, jwtValidator)
			if err != nil {
				log.Errorf("parsing token with claims: %v", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), "oid", claims["oid"]))

			next.ServeHTTP(w, r)
		})
	}
}

