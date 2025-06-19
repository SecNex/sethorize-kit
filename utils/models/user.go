package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/secnex/sethorize-kit/helper"
	"gorm.io/gorm"
)

type User struct {
	ID uuid.UUID `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()" json:"id"`
	// Only unique within a tenant
	Email       string `gorm:"not null;uniqueIndex:idx_email_tenant" json:"email"`
	FirstName   string `gorm:"not null" json:"first_name"`
	LastName    string `gorm:"not null" json:"last_name"`
	DisplayName string `gorm:"not null" json:"display_name"`
	Password    string `gorm:"not null" json:"password"`
	IsActive    bool   `gorm:"not null;default:true" json:"is_active"`
	IsVerified  bool   `gorm:"not null;default:false" json:"is_verified"`
	IsAdmin     bool   `gorm:"not null;default:false" json:"is_admin"`

	TenantID uuid.UUID `gorm:"not null;uniqueIndex:idx_email_tenant" json:"tenant_id"`

	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"autoDeleteTime" json:"deleted_at"`

	Tenant Tenant `gorm:"foreignKey:TenantID"`
}

func (User) TableName() string {
	return "users"
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	u.DisplayName = fmt.Sprintf("%s %s", u.FirstName, u.LastName)
	argon2 := helper.NewArgon2Default()
	hash, err := argon2.Hash(u.Password)
	if err != nil {
		return err
	}
	u.Password = hash
	return nil
}
