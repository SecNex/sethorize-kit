package auth

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/secnex/sethorize-kit/models"
)

type ClientRequest struct {
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id"`
}

type ClientResponse struct {
	Consent bool     `json:"consent"`
	Scopes  []string `json:"scopes"`
	models.Client
}

func (h *AuthHandler) Client(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var request ClientRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var client models.Client
	err = h.Handler.DB.Where("id = ? AND is_active = ?", request.ClientID, true).First(&client).Error
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var consent models.Consent
	_ = h.Handler.DB.Where("user_id = ? AND client_id = ?", request.UserID, request.ClientID).First(&consent).Error

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	consentID := false
	scopes := []string{}

	if consent.ID != uuid.Nil {
		consentID = true
		scopes = []string(consent.Scopes)
	}

	json.NewEncoder(w).Encode(ClientResponse{
		Consent: consentID,
		Scopes:  scopes,
		Client:  client,
	})
}
