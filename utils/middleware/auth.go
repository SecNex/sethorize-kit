package middleware

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/secnex/sethorize-kit/handler"
	"github.com/secnex/sethorize-kit/helper"
	"github.com/secnex/sethorize-kit/models"
	"gorm.io/gorm"
)

const tokenSecret = "your-256-bit-secret"

type AuthMiddleware struct {
	Handler *handler.Handler
}

func NewAuthMiddleware(db *gorm.DB) *AuthMiddleware {
	return &AuthMiddleware{Handler: handler.NewHandler(db)}
}

func (h *AuthMiddleware) ClientMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientAuth := r.Header.Get("Authorization")
		clientAuth = strings.TrimPrefix(clientAuth, "Bearer ")

		decodedClientAuth, err := base64.StdEncoding.DecodeString(clientAuth)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		clientID, clientSecret, ok := strings.Cut(string(decodedClientAuth), ":")
		if !ok {
			http.Error(w, "Invalid client authentication", http.StatusUnauthorized)
			return
		}

		var client models.Client
		err = h.Handler.DB.Where("id = ? AND is_active = ?", clientID, true).First(&client).Error
		if err != nil {
			http.Error(w, "Invalid client authentication", http.StatusUnauthorized)
			return
		}

		argon2 := helper.NewArgon2Default()
		ok, err = argon2.Compare(clientSecret, client.Secret)
		if err != nil {
			http.Error(w, "Invalid client authentication", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *AuthMiddleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.Header.Get("Authorization")
		accessToken = strings.TrimPrefix(accessToken, "Bearer ")

		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(tokenSecret), nil
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		sessionID := claims["sid"].(string)

		var session models.Session
		err = h.Handler.DB.Where("id = ? AND client_id = ? AND revoked_at IS NULL", sessionID, claims["aud"]).First(&session).Error
		if err != nil {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "session", session)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
