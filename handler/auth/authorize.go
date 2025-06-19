package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/secnex/sethorize-kit/models"
	"github.com/secnex/sethorize-kit/utils"
)

type AuthorizeRequest struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	ResponseType string `json:"response_type"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
}

type AuthorizeResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

func (h *AuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Authorize request")
	session := r.Context().Value("session").(models.Session)
	fmt.Println("Session:")
	fmt.Println(session)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request AuthorizeRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		fmt.Println("Invalid request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Request:")
	fmt.Println(request)

	var client models.Client
	err = h.Handler.DB.Where("id = ?", request.ClientID).First(&client).Error
	if err != nil {
		fmt.Println("Client not found")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !slices.Contains(client.RedirectURIs, request.RedirectURI) {
		fmt.Println("Invalid redirect URI")
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	if session.UserID == uuid.Nil {
		fmt.Println("Invalid session")
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	// Check if consent already exists for this client and user and delete it
	var consent models.Consent
	_ = h.Handler.DB.Where("user_id = ? AND client_id = ?", session.UserID, client.ID).First(&consent).Error

	if consent.ID != uuid.Nil {
		err = h.Handler.DB.Delete(&consent).Error
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	authCodeToken := utils.GenerateToken(32)

	authCode := models.AuthCode{
		ClientID:    client.ID,
		UserID:      session.UserID,
		Code:        authCodeToken,
		RedirectURI: request.RedirectURI,
		Scopes:      pq.StringArray(strings.Split(request.Scope, " ")),
	}

	err = h.Handler.DB.Create(&authCode).Scan(&authCode).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newConsent := models.Consent{
		UserID:     session.UserID,
		ClientID:   client.ID,
		AuthCodeID: authCode.ID,
		Scopes:     pq.StringArray(strings.Split(request.Scope, " ")),
	}

	var createdConsent models.Consent
	err = h.Handler.DB.Create(&newConsent).Scan(&createdConsent).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	bearerToken := fmt.Sprintf("%s:%s", authCode.ID.String(), authCodeToken)
	encodedBearerToken := base64.StdEncoding.EncodeToString([]byte(bearerToken))

	json.NewEncoder(w).Encode(AuthorizeResponse{Code: encodedBearerToken, State: request.State})
}
