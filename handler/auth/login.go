package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/secnex/sethorize-kit/helper"
	"github.com/secnex/sethorize-kit/models"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ClientID string `json:"client_id"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request LoginRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if request.ClientID == "" {
		http.Error(w, "Client ID is required", http.StatusBadRequest)
		return
	}

	var client models.Client
	// Check if clientId is a valid uuid (then search by id) or slug (then search by slug)
	if _, err := uuid.Parse(request.ClientID); err == nil {
		err = h.Handler.DB.Where("id = ?", request.ClientID).First(&client).Error
	} else {
		err = h.Handler.DB.Where("slug = ?", request.ClientID).First(&client).Error
	}

	if client.ID == uuid.Nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	var user models.User
	err = h.Handler.DB.Where("email = ? AND is_active = ? AND is_verified = ?", request.Username, true, true).First(&user).Error
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	argon2 := helper.NewArgon2Default()
	valid, err := argon2.Compare(request.Password, user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !valid {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	var tenant models.Tenant
	h.Handler.DB.Where("id = ?", user.TenantID).First(&tenant)

	session := models.Session{
		UserID:   user.ID,
		ClientID: client.ID,
	}

	var createdSession models.Session
	err = h.Handler.DB.Create(&session).Scan(&createdSession).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	exp := time.Now().Add(time.Minute * 60).Unix()

	jwt := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": user.ID,
		"aud": client.ID.String(),
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	expiresInSeconds := exp - time.Now().Unix()

	response := LoginResponse{
		AccessToken: tokenString,
		ExpiresIn:   int(expiresInSeconds),
		TokenType:   "Bearer",
		Scope:       "read",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
