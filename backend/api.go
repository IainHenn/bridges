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

	type User struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var userReq User

	err := c.BindJSON(&userReq)

	if err != nil {
		c.Status(400) // Bad user request
		return
	}

	db, err := getDBAccess()

	if err != nil {
		c.Status(500) // Server issue
		return
	}

	row := db.QueryRow("SELECT email, password FROM users WHERE email = $1 AND password = $2", userReq.Email, userReq.Password)
	err = row.Scan(&userReq.Email, &userReq.Password)

	if err != nil {
		fmt.Println("Error finding user!") //404 user not found
		c.Status(404)
		return
	}

	// If it reaches here then it was a success
	c.Status(200)
}

func signupUser(c *gin.Context) {

	type User struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var userReq User

	err := c.BindJSON(&userReq)

	if err != nil {
		c.Status(400) // Bad request from user
	}

	db, err := getDBAccess()

	if err != nil {
		c.Status(500) // Server issue on db
		return
	}

	//If email already exists you shouldn't be able to make multiple accounts
	row := db.QueryRow("SELECT email FROM users WHERE email = $1", userReq.Email)
	err = row.Scan(&userReq.Email)

	//If email does not exist
	if err == sql.ErrNoRows {
		_, err := db.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", userReq.Email, userReq.Password)
		if err != nil {
			fmt.Println("Error inserting user:", err) // Insertion issue, server error
			c.Status(500)
			return
		}
		c.Status(201)
		return
	} else if err != nil {
		fmt.Println("Error inserting user:", err) // Any sort of error, return server issue
		c.Status(500)
		return
	} else {
		c.Status(422) //Entity already exists, entity error
		return
	}
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
