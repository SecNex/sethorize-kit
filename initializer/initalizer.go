package initializer

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/secnex/sethorize-kit/models"
	"github.com/secnex/sethorize-kit/utils"
	"gorm.io/gorm"
)

type Initializer struct {
	DB              *gorm.DB
	Domain          string
	ApplicationName string
}

func NewInitializer(db *gorm.DB) *Initializer {
	domain := os.Getenv("APPLICATION_DOMAIN")
	applicationName := os.Getenv("APPLICATION_NAME")
	return &Initializer{
		DB:              db,
		Domain:          domain,
		ApplicationName: applicationName,
	}
}

func (i *Initializer) Initialize() {
	fmt.Println("Initializing basic data...")

	// 1. Create default tenant
	tenantID := i.createDefaultTenant()

	// 2. Create default clients
	i.createDefaultClient(tenantID)
	i.createCLIClient(tenantID)
	i.createAccountClient(tenantID)

	// 3. Create admin user
	i.createAdminUser(tenantID)

	fmt.Println("DONE!")
}

func (i *Initializer) createDefaultTenant() uuid.UUID {
	tenantName := i.ApplicationName
	var tenant models.Tenant

	// Check if tenant already exists
	err := i.DB.Where("name = ?", tenantName).First(&tenant).Error
	if err == nil {
		fmt.Printf("Tenant '%s' already exists (ID: %s)", tenantName, tenant.ID)
		return tenant.ID
	}

	// Create new tenant
	newTenant := models.Tenant{
		Name: tenantName,
	}

	var createdTenant models.Tenant
	err = i.DB.Create(&newTenant).Scan(&createdTenant).Error
	if err != nil {
		fmt.Printf("Error creating tenant: %v", err)
		return uuid.Nil
	}

	fmt.Printf("Tenant '%s' created (ID: %s)", tenantName, createdTenant.ID)
	return createdTenant.ID
}

func (i *Initializer) createDefaultClient(tenantID uuid.UUID) {
	clientName := fmt.Sprintf("%s Client", i.ApplicationName)
	clientSlug := "default"

	var client models.Client

	// Check if client already exists
	err := i.DB.Where("slug = ? AND tenant_id = ?", clientSlug, tenantID).First(&client).Error
	if err == nil {
		fmt.Printf("Default Client already exists (ID: %s)", client.ID)
		return
	}

	// Create default client
	token := utils.GenerateToken(32)
	newClient := models.Client{
		Name:         clientName,
		Slug:         clientSlug,
		Description:  "Default OAuth2 Client",
		RedirectURIs: []string{},
		Secret:       token,
		TenantID:     tenantID,
		Internal:     false,
	}

	var createdClient models.Client
	err = i.DB.Create(&newClient).Scan(&createdClient).Error
	if err != nil {
		fmt.Printf("Error creating default client: %v", err)
		return
	}

	fmt.Printf("Default Client created (ID: %s, Secret: %s)", createdClient.ID, token)
}

func (i *Initializer) createCLIClient(tenantID uuid.UUID) {
	clientName := fmt.Sprintf("%s CLI Client", i.ApplicationName)

	clientSlug := fmt.Sprintf("%s-cli", strings.ToLower(i.ApplicationName))
	var client models.Client

	// Check if client already exists
	err := i.DB.Where("slug = ? AND tenant_id = ?", clientSlug, tenantID).First(&client).Error
	if err == nil {
		fmt.Printf("CLI Client already exists (ID: %s)", client.ID)
		return
	}

	// Create CLI client
	token := utils.GenerateToken(32)
	newClient := models.Client{
		Name:         clientName,
		Slug:         clientSlug,
		Description:  "Command Line Interface Client",
		RedirectURIs: []string{},
		Secret:       token,
		TenantID:     tenantID,
		Internal:     true,
	}

	var createdClient models.Client
	err = i.DB.Create(&newClient).Scan(&createdClient).Error
	if err != nil {
		fmt.Printf("Error creating CLI client: %v", err)
		return
	}

	fmt.Printf("CLI Client created (ID: %s, Secret: %s)", createdClient.ID, token)
}

func (i *Initializer) createAccountClient(tenantID uuid.UUID) {
	clientName := fmt.Sprintf("%s Account Client", i.ApplicationName)
	clientSlug := "account"
	var client models.Client

	// Check if client already exists
	err := i.DB.Where("slug = ? AND tenant_id = ?", clientSlug, tenantID).First(&client).Error
	if err == nil {
		fmt.Printf("Account Client already exists (ID: %s)", client.ID)
		return
	}

	// Create account client
	token := utils.GenerateToken(32)
	newClient := models.Client{
		Name:         clientName,
		Slug:         clientSlug,
		Description:  "Account Management Client",
		RedirectURIs: []string{},
		Secret:       token,
		TenantID:     tenantID,
		Internal:     true,
	}

	err = i.DB.Create(&newClient).Scan(&newClient).Error
	if err != nil {
		fmt.Printf("Error creating account client: %v", err)
		return
	}

	fmt.Printf("Account Client created (ID: %s, Secret: %s)", newClient.ID, token)
}

func (i *Initializer) createAdminUser(tenantID uuid.UUID) {
	email := fmt.Sprintf("admin@%s", i.Domain)
	var user models.User

	// Check if admin user already exists
	err := i.DB.Where("email = ? AND tenant_id = ?", email, tenantID).First(&user).Error
	if err == nil {
		fmt.Printf("Admin User already exists (ID: %s)", user.ID)
		return
	}

	// Create admin user
	newUser := models.User{
		FirstName:   "Admin",
		LastName:    "User",
		DisplayName: "Administrator",
		Email:       email,
		Password:    "Admin,2025!",
		IsActive:    true,
		IsVerified:  true,
		IsAdmin:     true,
		TenantID:    tenantID,
	}

	var createdUser models.User
	err = i.DB.Create(&newUser).Scan(&createdUser).Error
	if err != nil {
		fmt.Printf("Error creating admin user: %v", err)
		return
	}

	fmt.Printf("Admin User created (ID: %s, Email: %s)", createdUser.ID, email)
}
