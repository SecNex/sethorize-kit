package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/secnex/sethorize-kit/helper"
	"github.com/secnex/sethorize-kit/models"
	"github.com/secnex/sethorize-kit/utils"
)

type TokenRequest struct {
	GrantType    string  `json:"grant_type"`
	RedirectURI  *string `json:"redirect_uri"`
	ClientID     string  `json:"client_id"`
	ClientSecret string  `json:"client_secret"`
	Code         *string `json:"code"`
	RefreshToken *string `json:"refresh_token"`
	Scope        *string `json:"scope"`
}

type RefreshTokenRequest struct {
	GrantType    string  `json:"grant_type"`
	RefreshToken *string `json:"refresh_token"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type ClientCredentialsRequest struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

func (h *AuthHandler) AuthorizationCodeFlow(w http.ResponseWriter, request TokenRequest) {
	// Decode the bearer token
	bearerToken, err := base64.StdEncoding.DecodeString(*request.Code)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Split the bearer token into id and code
	parts := strings.Split(string(bearerToken), ":")
	if len(parts) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	authCodeID := parts[0]
	authCodeToken := parts[1]

	var authCode models.AuthCode
	err = h.Handler.DB.Where("id = ? AND used_at IS NULL", authCodeID).First(&authCode).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	argon2 := helper.NewArgon2Default()
	authCodeValid, err := argon2.Compare(authCodeToken, authCode.Code)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !authCodeValid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if authCode.ExpiresAt.Before(time.Now()) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	authCode.UsedAt = time.Now()
	err = h.Handler.DB.Save(&authCode).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var user models.User
	err = h.Handler.DB.Where("id = ? AND is_active = ? AND is_verified = ? AND deleted_at IS NULL", authCode.UserID, true, true).First(&user).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var tenant models.Tenant
	err = h.Handler.DB.Where("id = ?", user.TenantID).First(&tenant).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var client models.Client
	err = h.Handler.DB.Where("id = ? AND is_active = ? AND deleted_at IS NULL", authCode.ClientID, true).First(&client).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	clientSecretValid, err := argon2.Compare(request.ClientSecret, client.Secret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !clientSecretValid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	session := models.Session{
		UserID:   authCode.UserID,
		ClientID: authCode.ClientID,
	}

	var createdSession models.Session
	err = h.Handler.DB.Create(&session).Scan(&createdSession).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	refreshTokenValue := utils.GenerateToken(32)

	refreshToken := models.RefreshToken{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Token:    refreshTokenValue,
	}

	var createdRefreshToken models.RefreshToken
	err = h.Handler.DB.Create(&refreshToken).Scan(&createdRefreshToken).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	bearerRefreshToken := base64.StdEncoding.EncodeToString([]byte(createdRefreshToken.ID.String() + ":" + createdRefreshToken.Token))

	exp := time.Now().Add(time.Minute * 60).Unix()

	jwt := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": session.UserID,
		"aud": session.ClientID.String(),
		"iss": "sethorize-idp-api",
		"iat": time.Now().Unix(),
		"exp": exp,
		"sid": createdSession.ID.String(),
		"user": map[string]interface{}{
			"first_name":   user.FirstName,
			"last_name":    user.LastName,
			"display_name": user.DisplayName,
			"email":        user.Email,
			"id":           user.ID,
			"tenant_id":    user.TenantID,
			"tenant_name":  tenant.Name,
			"is_admin":     user.IsAdmin,
		},
	})

	tokenString, err := jwt.SignedString(h.KeyManager.GetPrivateKey())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken:  tokenString,
		RefreshToken: bearerRefreshToken,
		ExpiresIn:    3600,
	})
}

func (h *AuthHandler) RefreshTokenFlow(w http.ResponseWriter, request TokenRequest) {
	argon2 := helper.NewArgon2Default()
	bearerToken, err := base64.StdEncoding.DecodeString(*request.RefreshToken)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	parts := strings.Split(string(bearerToken), ":")
	if len(parts) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	refreshTokenID := parts[0]
	refreshTokenValue := parts[1]

	var refreshToken models.RefreshToken
	err = h.Handler.DB.Where("id = ? AND expires_at > ? AND revoked_at IS NULL AND used_at IS NULL", refreshTokenID, time.Now()).First(&refreshToken).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	refreshToken.UsedAt = time.Now()
	err = h.Handler.DB.Save(&refreshToken).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var user models.User
	err = h.Handler.DB.Where("id = ? AND is_active = ? AND is_verified = ? AND deleted_at IS NULL", refreshToken.UserID, true, true).First(&user).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var tenant models.Tenant
	err = h.Handler.DB.Where("id = ? AND is_active = ? AND deleted_at IS NULL", user.TenantID, true).First(&tenant).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var client models.Client
	err = h.Handler.DB.Where("id = ? AND is_active = ? AND deleted_at IS NULL", refreshToken.ClientID, true).First(&client).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	clientSecretValid, err := argon2.Compare(request.ClientSecret, client.Secret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !clientSecretValid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	refreshTokenValid, err := argon2.Compare(refreshTokenValue, refreshToken.Token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !refreshTokenValid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	session := models.Session{
		UserID:   refreshToken.UserID,
		ClientID: refreshToken.ClientID,
	}

	var createdSession models.Session
	err = h.Handler.DB.Create(&session).Scan(&createdSession).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	newRefreshTokenValue := utils.GenerateToken(32)

	newRefreshToken := models.RefreshToken{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Token:    newRefreshTokenValue,
	}

	var createdRefreshToken models.RefreshToken
	err = h.Handler.DB.Create(&newRefreshToken).Scan(&createdRefreshToken).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	bearerRefreshToken := base64.StdEncoding.EncodeToString([]byte(createdRefreshToken.ID.String() + ":" + createdRefreshToken.Token))

	exp := time.Now().Add(time.Minute * 60).Unix()

	jwt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": session.UserID,
		"aud": session.ClientID.String(),
		"iss": "sethorize-idp-api",
		"iat": time.Now().Unix(),
		"exp": exp,
		"sid": createdSession.ID.String(),
		"user": map[string]interface{}{
			"first_name":   user.FirstName,
			"last_name":    user.LastName,
			"display_name": user.DisplayName,
			"email":        user.Email,
			"id":           user.ID,
			"tenant_id":    user.TenantID,
			"tenant_name":  tenant.Name,
			"is_admin":     user.IsAdmin,
		},
	})

	tokenString, err := jwt.SignedString(h.KeyManager.GetPrivateKey())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expiresInSeconds := exp - time.Now().Unix()

	response := TokenResponse{
		AccessToken:  tokenString,
		RefreshToken: bearerRefreshToken,
		ExpiresIn:    int(expiresInSeconds),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) ClientCredentialsFlow(w http.ResponseWriter, request TokenRequest) {
	argon2 := helper.NewArgon2Default()

	var client models.Client
	err := h.Handler.DB.Where("id = ? AND is_active = ? AND deleted_at IS NULL", request.ClientID, true).First(&client).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	clientSecretValid, err := argon2.Compare(request.ClientSecret, client.Secret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !clientSecretValid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	session := models.Session{
		ClientID: client.ID,
	}

	var createdSession models.Session
	err = h.Handler.DB.Create(&session).Scan(&createdSession).Error
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	exp := time.Now().Add(time.Minute * 60).Unix()

	jwt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   session.ClientID,
		"aud":   session.ClientID.String(),
		"iss":   "sethorize-idp-api",
		"iat":   time.Now().Unix(),
		"exp":   exp,
		"sid":   createdSession.ID.String(),
		"type":  "client_credentials",
		"scope": client.Scopes,
	})

	tokenString, err := jwt.SignedString(h.KeyManager.GetPrivateKey())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	response := ClientCredentialsRequest{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   int(exp - time.Now().Unix()),
		Scope:       strings.Join(client.Scopes, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	redirectURI := r.Form.Get("redirect_uri")
	scope := r.Form.Get("scope")
	request := TokenRequest{
		GrantType:    r.Form.Get("grant_type"),
		ClientID:     r.Form.Get("client_id"),
		ClientSecret: r.Form.Get("client_secret"),
	}

	if code := r.Form.Get("code"); code != "" {
		request.Code = &code
		request.RedirectURI = &redirectURI
		request.Scope = &scope
	}
	if refreshToken := r.Form.Get("refresh_token"); refreshToken != "" {
		request.RefreshToken = &refreshToken
	}

	switch request.GrantType {
	case "authorization_code":
		h.AuthorizationCodeFlow(w, request)
	case "refresh_token":
		h.RefreshTokenFlow(w, request)
	case "client_credentials":
		h.ClientCredentialsFlow(w, request)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}
