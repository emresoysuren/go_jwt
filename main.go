package main

import (
	"github.com/emresoysuren/go_jwt/controllers"
	"github.com/emresoysuren/go_jwt/initializers"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.Login)

	r.Run() // listen and serve on 0.0.0.0:8080
}
