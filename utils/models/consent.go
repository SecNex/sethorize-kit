package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type Consent struct {
	ID         uuid.UUID      `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()" json:"id"`
	UserID     uuid.UUID      `gorm:"not null" json:"user_id"`
	ClientID   uuid.UUID      `gorm:"not null" json:"client_id"`
	AuthCodeID uuid.UUID      `gorm:"not null" json:"code_id"`
	Scopes     pq.StringArray `gorm:"type:text[];default:null" json:"scopes"`
	ExpiresAt  time.Time      `gorm:"type:timestamp;not null" json:"expires_at"`
	CreatedAt  time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt  time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"autoDeleteTime" json:"deleted_at"`

	User     User     `gorm:"foreignKey:UserID"`
	Client   Client   `gorm:"foreignKey:ClientID"`
	AuthCode AuthCode `gorm:"foreignKey:AuthCodeID"`
}

func (Consent) TableName() string {
	return "consents"
}

func (c *Consent) BeforeCreate(tx *gorm.DB) (err error) {
	c.ExpiresAt = time.Now().Add(time.Hour * 24 * 30)
	return nil
}
