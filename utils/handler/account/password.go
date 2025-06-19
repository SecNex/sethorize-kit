package account

import (
	"encoding/json"
	"net/http"

	"github.com/secnex/sethorize-kit/helper"
	"github.com/secnex/sethorize-kit/models"
)

type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *AccountHandler) PasswordChange(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(models.Session)

	var request PasswordChangeRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var user models.User
	err = h.Handler.DB.Where("id = ?", session.UserID).First(&user).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	argon2 := helper.NewArgon2Default()
	verifyOldPassword, err := argon2.Compare(request.CurrentPassword, user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !verifyOldPassword {
		http.Error(w, "Invalid current password", http.StatusBadRequest)
		return
	}

	hash, err := argon2.Hash(request.NewPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user.Password = hash
	h.Handler.DB.Save(&user)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password changed successfully",
	})
}
