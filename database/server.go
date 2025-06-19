package database

import (
	"fmt"

	"github.com/secnex/sethorize-kit/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type ServerConnection struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
}

type Server struct {
	Connection ServerConnection
	DB         *gorm.DB
}

func NewServer(connection ServerConnection) *Server {
	return &Server{
		Connection: connection,
	}
}

func (s *Server) Connect() *gorm.DB {
	db, err := gorm.Open(postgres.Open(s.Connection.ConnectionString()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		panic("failed to connect database")
	}
	s.DB = db

	fmt.Println("Migrating models...")

	// Aktiviere UUID-Extension
	s.DB.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")

	// Migriere in der richtigen Reihenfolge (Dependencies zuerst)
	db.AutoMigrate(
		&models.Tenant{},
		&models.User{},
		&models.Client{},
		&models.Session{},
		&models.AuthCode{},
		&models.RefreshToken{},
		&models.Consent{},
	)

	return db
}

func (s *ServerConnection) ConnectionString() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", s.Host, s.Port, s.User, s.Password, s.Database)
}

func (s *Server) AutoMigrate(models ...interface{}) {
	s.DB.AutoMigrate(models...)
}
