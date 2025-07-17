package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"

	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// Helper functions
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

func getStartingId(db *sql.DB, tableName string) int {
	var id int
	query := fmt.Sprintf("SELECT COALESCE(MAX(id), 0) + 1 FROM %s", tableName)
	err := db.QueryRow(query).Scan(&id)
	if err != nil {
		return 1 // fallback to 1 if error
	}
	return id
}

func decodeHexString(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	_, err := fmt.Sscanf(s, "%x", &b)
	return b, err
}

// Middleware
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		for _, cookie := range c.Request.Cookies() {
			fmt.Printf("🍪 Cookie received: %s = %s\n", cookie.Name, cookie.Value)
		}

		verificationToken, err := c.Cookie("token")

		if err != nil {
			c.Status(500)
			c.Abort()
			return
		}

		db, err := getDBAccess()

		if err != nil {
			c.Status(500)
			c.Abort()
			return
		}

		defer db.Close()

		row := db.QueryRow(`SELECT email, salt, nonce, encrypted_key FROM users u
					JOIN verification_tokens vt ON vt.user_id = u.id
					WHERE token = $1
					AND expiration_date >= NOW()
					AND verified = TRUE`, (verificationToken))

		var email string
		var salt string
		var nonce string
		var encrypted_key string

		err = row.Scan(&email, &salt, &nonce, &encrypted_key)

		if err == sql.ErrNoRows {
			c.Status(401)
			c.Abort()
			return
		} else if err != nil {
			c.Status(500)
			c.Abort()
			return
		}

		c.Set("email", email)
		emailVal, _ := c.Get("email")
		fmt.Println("Authenticated email:", emailVal)
		c.Set("salt", salt)
		c.Set("nonce", nonce)
		c.Set("encrypted_key", encrypted_key)
		c.Next()
	}
}

// REST Routes
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

	var hashedPassword string

	row := db.QueryRow("SELECT password FROM users WHERE email = $1", userReq.Email)
	err = row.Scan(&hashedPassword)

	if err != nil {
		fmt.Println("Error finding user!") //404 user not found
		c.Status(404)
		return
	}

	if err == sql.ErrNoRows {
		c.Status(500)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(userReq.Password))

	if err != nil {
		c.Status(401)
		return
	}

	fmt.Println("this made it here")
	// If it reaches here then it was a success
	c.Status(200)
}

func signupUser(c *gin.Context) {

	type User struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		Salt         string `json:"salt"`
		Nonce        string `json:"nonce"`
		EncryptedKey string `json:"encryptedKey"`
		PublicKey    string `json:"publicKey"`
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
		VALUES ($1, $2, $3, $4, $5, $6)`, userReq.Email, hashedPassword, userReq.PublicKey, userReq.EncryptedKey, userReq.Salt, userReq.Nonce)
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
		fmt.Println(err)
		c.Status(422) //Entity already exists, entity error
		return
	}
}

func generateToken(c *gin.Context) {
	type User struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	db, err := getDBAccess()

	if err != nil {
		c.Status(500)
	}

	var userReq User

	err = c.BindJSON(&userReq)

	if err != nil {
		c.Status(400)
		return
	}

	claims := jwt.MapClaims{
		"sub": userReq.Email,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secretKey := os.Getenv("JWT_SECRET_KEY")
	tokenString, err := token.SignedString([]byte(secretKey))

	if err != nil {
		fmt.Println("failed to create a token")
		c.Status(500)
		return
	}

	//Need to get the user's ID
	var userId int
	row := db.QueryRow("SELECT id FROM users WHERE email = $1", userReq.Email)
	err = row.Scan(&userId)

	if err == sql.ErrNoRows {
		c.Status(404) // User does not exist
		return
	}

	//Check if that user already has a token that has been generated before
	var exists string
	row = db.QueryRow("SELECT token FROM verification_tokens WHERE user_id = $1 AND type = 'VERIFICATION'", userId)
	err = row.Scan(&exists)

	// verification token hasn't been created for user
	if err == sql.ErrNoRows {
		//Use that user's ID, token, and other details and send it to the database
		starterTableId := getStartingId(db, "verification_tokens")
		_, err := db.Exec(`INSERT INTO verification_tokens (id, expiration_date, token, verified, user_id, type)
				VALUES ($1, $2, $3, $4, $5, $6)`,
			starterTableId, time.Now().Add(time.Hour), tokenString, true, userId, "VERIFICATION")

		if err != nil {
			fmt.Println("failed to insert token into table:", err)
			c.Status(500) // Server error
			return
		}
	} else {
		// Verification token has been created for user, so we're updated it
		_, err := db.Exec(`UPDATE verification_tokens
				SET expiration_date = $1,
					token = $2, 
					verified = $3
				WHERE user_id = $4 AND type = 'VERIFICATION'`,
			time.Now().Add(time.Hour),
			tokenString,
			true,
			userId)

		if err != nil {
			fmt.Println("Failed to update verification token in table")
			c.Status(500) // Server error
			return
		}
	}
	//Send back the tokenstring to store in the frontend
	c.JSON(200, gin.H{
		"token": tokenString,
	})
}

type TokenRequest struct {
	Token string `json:"token"`
}

func setTokenCookieHandler(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    req.Token,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false, // Set to true if using HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	c.Status(http.StatusOK)
}

func retrieveChallenge(c *gin.Context) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		fmt.Println("this was the failure")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate nonce"})
		return
	}
	c.JSON(200, gin.H{
		"nonce": base64.StdEncoding.EncodeToString(nonce),
	})
}

type SignatureRequest struct {
	Signature string `json:"signature"`
	Challenge string `json:"challenge"`
}

func verifySignature(c *gin.Context) {
	fmt.Println("verifySignature called")
	var req SignatureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Println("Failed to bind JSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	email, exists := c.Get("email")
	if !exists {
		fmt.Println("Email not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email not found in context"})
		return
	}

	fmt.Println("Email from context:", email)

	db, err := getDBAccess()
	if err != nil {
		fmt.Println("Failed to get DB access:", err)
		c.Status(500)
		return
	}

	var publicKey string
	emailStr, ok := email.(string)
	if !ok {
		fmt.Println("Email in context is not a string")
		c.Status(500)
		return
	}
	fmt.Println("Querying public key for email:", emailStr)
	row := db.QueryRow("SELECT pub_key FROM users WHERE email = $1", emailStr)
	err = row.Scan(&publicKey)

	if err == sql.ErrNoRows {
		fmt.Println("No row found for email:", emailStr)
		c.Status(404)
		return
	} else if err != nil {
		fmt.Println("Error scanning public key:", err)
		c.Status(500)
		return
	}

	fmt.Println("Public key retrieved:", publicKey)

	// Decode public key from base64
	pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		fmt.Println("Failed to decode public key from base64:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid public key format"})
		return
	}

	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		fmt.Println("Failed to parse public key:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse public key"})
		return
	}

	// Decode the signature from base64
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		fmt.Println("Failed to decode signature from base64:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature encoding"})
		return
	}
	// Decode challenge from base64 to bytes
	challengeBytes, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil {
		fmt.Println("Failed to decode challenge from base64:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid challenge encoding"})
		return
	}

	fmt.Println("Signature and challenge decoded")

	hashed := sha256.Sum256(challengeBytes)
	fmt.Println("Challenge hashed")

	switch pk := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("Verifying RSA signature")
		err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, hashed[:], sigBytes)
		if err != nil {
			fmt.Println("RSA signature verification failed:", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Signature verification failed"})
			return
		}
		fmt.Println("RSA signature verified successfully")
	case *ecdsa.PublicKey:
		fmt.Println("Verifying ECDSA signature")
		if len(sigBytes) == 0 {
			fmt.Println("ECDSA signature is empty")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Empty signature"})
			return
		}
		if ecdsa.VerifyASN1(pk, hashed[:], sigBytes) {
			fmt.Println("ECDSA signature verified successfully")
			c.JSON(http.StatusOK, gin.H{"success": true})
			return
		} else {
			fmt.Println("ECDSA signature verification failed")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Signature verification failed"})
			return
		}
	default:
		fmt.Println("Unsupported public key type")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported public key type"})
		return
	}

	fmt.Println("Signature verified successfully, returning OK")
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func main() {
	fmt.Println("Starting server on port 8080...")
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	router.POST("/sessions", loginUser)                  // POST /sessions to create a session (login)
	router.POST("/users", signupUser)                    // POST /users to create a user (signup)
	router.POST("/tokens", generateToken)                // POST /tokens to create a token
	router.POST("/token-cookies", setTokenCookieHandler) // POST /token-cookies to set a token cookie
	router.GET("/api/challenge", AuthMiddleware(), retrieveChallenge)
	router.POST("/signatures/verify", AuthMiddleware(), verifySignature)
	router.Run("localhost:8080")
}
