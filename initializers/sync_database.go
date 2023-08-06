package initializers

import "github.com/emresoysuren/go_jwt/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
