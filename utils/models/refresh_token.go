package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/secnex/sethorize-kit/helper"
	"gorm.io/gorm"
)

type RefreshToken struct {
	ID        uuid.UUID `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()" json:"id"`
	UserID    uuid.UUID `gorm:"not null" json:"user_id"`
	ClientID  uuid.UUID `gorm:"not null" json:"client_id"`
	Token     string    `gorm:"not null" json:"token"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	RevokedAt time.Time `gorm:"type:timestamp;default:null" json:"revoked_at"`
	UsedAt    time.Time `gorm:"type:timestamp;default:null" json:"used_at"`

	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"autoDeleteTime" json:"deleted_at"`

	User   User   `gorm:"foreignKey:UserID"`
	Client Client `gorm:"foreignKey:ClientID"`
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

func (u *RefreshToken) BeforeCreate(tx *gorm.DB) (err error) {
	u.ExpiresAt = time.Now().Add(time.Hour * 24)

	argon2 := helper.NewArgon2Default()
	hash, err := argon2.Hash(u.Token)
	if err != nil {
		return err
	}

	u.Token = hash

	return nil
}
