package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Session struct {
	ID        uuid.UUID      `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()" json:"id"`
	UserID    uuid.UUID      `gorm:"default:null" json:"user_id"`
	ClientID  uuid.UUID      `gorm:"not null" json:"client_id"`
	ExpiresAt time.Time      `gorm:"not null" json:"expires_at"`
	RevokedAt time.Time      `gorm:"default:null" json:"revoked_at"`
	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"autoDeleteTime" json:"deleted_at"`

	User   User   `gorm:"foreignKey:UserID"`
	Client Client `gorm:"foreignKey:ClientID"`
}

func (Session) TableName() string {
	return "sessions"
}
