package middleware

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/emresoysuren/go_jwt/initializers"
	"github.com/emresoysuren/go_jwt/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(c *gin.Context) {
	// Get the cookie off request
	tokenString, err := c.Cookie("Authorization")
	if err != nil {
		log.Println("Authorization cookie is not found:", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Decode and validate it
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		key := os.Getenv("SECRET_KEY")
		return []byte(key), nil
	})

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		log.Println("Authorization token is not valid:", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Check the exp
	exp, ok := claims["exp"].(float64)
	if !ok {
		log.Println("Authorization token is not valid:", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	if float64(time.Now().Unix()) > exp {
		log.Println("Authorization token is expeired:", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Find the user with token sub
	var user models.User
	initializers.DB.First(&user, claims["sub"])

	if user.ID == 0 {
		log.Println("Authorization token is not valid:", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Attach to req
	c.Set("user", user)

	// Continue
	c.Next()
}
