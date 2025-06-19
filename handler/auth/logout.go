package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/secnex/sethorize-kit/models"
)

type LogoutResponse struct {
	Message string `json:"message"`
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session := r.Context().Value("session").(models.Session)

	err := h.Handler.DB.Model(&session).Update("revoked_at", time.Now()).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LogoutResponse{Message: "OK"})
}
