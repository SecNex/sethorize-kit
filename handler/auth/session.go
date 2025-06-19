package auth

import (
	"encoding/json"
	"net/http"

	"github.com/secnex/sethorize-kit/models"
)

type SessionResponse struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

func (h *AuthHandler) Session(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := r.Context().Value("session").(models.Session)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SessionResponse{Message: "OK", ID: session.ID.String()})
}
