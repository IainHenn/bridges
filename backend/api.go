package main

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"

	"golang.org/x/crypto/bcrypt"

	"golang.org/x/crypto/pbkdf2"
)

func encryptPrivateKey(pemBytes []byte, password string) ([]byte, error) {
	// Derive key from password using PBKDF2
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := pbkdf2.Key([]byte(password), salt, 100_000, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, pemBytes, nil)

	// Prepend salt so you can derive key during decryption
	return append(salt, ciphertext...), nil
}

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

	//Create pubkey for user
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		c.Status(500) // private key failed to create
		return
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// encryptedKey is salt + nonce + encrypted private key
	encryptedKey, err := encryptPrivateKey(privBytes, userReq.Password)

	pubBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	pubPrem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubBytes,
	})

	if err != nil {
		c.Status(500)
	}

	//If email does not exist
	salt := base64.RawStdEncoding.EncodeToString(encryptedKey[:16])
	nonce := base64.RawStdEncoding.EncodeToString(encryptedKey[16 : 16+12])
	ciphertext := base64.RawStdEncoding.EncodeToString(encryptedKey[16+12:])
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(userReq.Password), 10)
	if err != nil {
		c.Status(500)
	}
	hashedPassword := string(hashedPasswordBytes)

	//If email already exists you shouldn't be able to make multiple accounts
	row := db.QueryRow("SELECT email FROM users WHERE email = $1", userReq.Email)
	err = row.Scan(&userReq.Email)

	if err == sql.ErrNoRows {
		_, err := db.Exec(`INSERT INTO users (
			email, 
			password, 
			pub_key, 
			encrypted_key, 
			salt, 
			nonce)  
		VALUES ($1, $2, $3, $4, $5, $6)`, userReq.Email, hashedPassword, string(pubPrem), ciphertext, salt, nonce)
		if err != nil {
			fmt.Println("Error inserting user:", err) // Insertion issue, server error
			c.Status(500)
			return
		}
		c.IndentedJSON(201, gin.H{"salt": salt, "nonce": nonce, "ciphertext": ciphertext})
		return
	} else if err != nil {
		fmt.Println("Error inserting user:", err) // Any sort of error, return server issue
		c.Status(500)
		return
	} else {
		fmt.Println(err)
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
