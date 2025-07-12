package main

import (
	"fmt"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func getHi(c *gin.Context) {
	fmt.Println("Hi")
}

func main() {
	fmt.Println("Starting server on port 8080...")
	router := gin.Default()
	router.Use(cors.Default())
	router.GET("/hi", getHi)
	router.Run("0.0.0.0:8080")
	fmt.Println("Running!")
}
