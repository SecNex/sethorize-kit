package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/secnex/sethorize-kit/helper"
	"gorm.io/gorm"
)

type Client struct {
	ID           uuid.UUID      `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()" json:"id"`
	Name         string         `gorm:"not null;uniqueIndex:idx_name_tenant" json:"name"`
	Slug         string         `gorm:"not null;uniqueIndex:idx_slug_tenant" json:"slug"`
	Description  string         `gorm:"not null" json:"description"`
	Secret       string         `gorm:"not null" json:"secret"`
	RedirectURIs pq.StringArray `gorm:"type:text[]" json:"redirect_uris"`
	Scopes       pq.StringArray `gorm:"type:text[]" json:"scopes"`
	IsActive     bool           `gorm:"not null;default:true" json:"is_active"`
	Internal     bool           `gorm:"not null;default:false" json:"internal"`
	TenantID     uuid.UUID      `gorm:"type:uuid;not null;uniqueIndex:idx_name_tenant;uniqueIndex:idx_slug_tenant" json:"tenant_id"`
	CreatedAt    time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"autoDeleteTime" json:"deleted_at"`

	Tenant *Tenant `gorm:"foreignKey:TenantID"`
}

func (Client) TableName() string {
	return "clients"
}

func (c *Client) BeforeCreate(tx *gorm.DB) (err error) {
	argon2 := helper.NewArgon2Default()
	hash, err := argon2.Hash(c.Secret)
	if err != nil {
		return err
	}
	c.Secret = hash
	return nil
}
