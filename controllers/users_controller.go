package controllers

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/emresoysuren/go_jwt/initializers"
	"github.com/emresoysuren/go_jwt/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(c *gin.Context) {
	// Get the email and password off request body
	var body struct {
		Email    string
		Password string
	}

	err := c.Bind(&body)
	if err != nil {
		log.Println("Failed to read body:", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		log.Println("Failed to hash password:", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	// Create the user
	user := models.User{
		Email:    body.Email,
		Password: string(hash),
	}
	result := initializers.DB.Create(&user)
	if result.Error != nil {
		log.Println("Failed to create user:", result.Error)
		c.JSON(400, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	// Respond
	c.JSON(200, gin.H{})
}

func Login(c *gin.Context) {
	// Get the email and password off request body
	var body struct {
		Email    string
		Password string
	}

	err := c.Bind(&body)
	if err != nil {
		log.Println("Failed to read body:", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	// Look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)
	if user.ID == 0 {
		log.Println("Failed to find the user:", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to find the user",
		})
		return
	}

	// Compare sent in pass with saved user hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		log.Println("Invalid password:", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid password",
		})
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	key := os.Getenv("SECRET_KEY")
	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		log.Println("Failed to create token:", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	// Send it back
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"Authorization",
		tokenString,
		3600*24*30,
		"",
		"",
		true,
		true,
	)

	c.JSON(200, gin.H{
		"token": tokenString,
	})
}
