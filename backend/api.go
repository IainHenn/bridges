package main

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

func getDBAccess() (*sql.DB, error) {
	dbUser := os.Getenv("DB_USER")
	dbPW := os.Getenv("DB_PW")
	dbHost := os.Getenv("DB_HOST")
	dbName := os.Getenv("DB_NAME")

	connectionStr := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", dbUser, dbPW, dbHost, dbName)
	db, err := sql.Open("postgres", connectionStr)

	if err != nil {
		fmt.Println("Error opening database:", err)
		return db, err
	}

	err = db.Ping()
	if err != nil {
		fmt.Println("Error connecting to database:", err)
		return db, err
	}
	return db, nil
}

func loginUser(c *gin.Context) {

	userEmail := c.Query("email")
	userPassword := c.Query("password")

	db, err := getDBAccess()

	if err != nil {
		c.Status(500)
	}

	// Definition of a user
	type user struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Assigning user struct
	u := user{
		userEmail,
		userPassword,
	}

	//Checking if the user exists, if they don't return
	row := db.QueryRow("SELECT email, password FROM users WHERE email = ? and password = ?", u.Email, u.Password)
	err = row.Scan(&u.Email, &u.Password)

	if err != nil {
		fmt.Println("Error finding user!")
		c.Status(404)
	}

	// If it reaches here then it was a success
	c.Status(200)
}

func signupUser(c *gin.Context) {
	inputtedEmail := c.Query("inputtedEmail")
	inputtedPassword := c.Query("inputtedPassword")
}

func main() {
	fmt.Println("Starting server on port 8080...")
	router := gin.Default()
	router.Use(cors.Default())
	router.POST("/sessions", loginUser)
	router.POST("/users", signupUser)
	router.Run("localhost:8080")
	fmt.Println("Running!")
}
