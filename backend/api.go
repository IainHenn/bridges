package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/joho/godotenv"
)

// Helper functions
func initDynamoDB() (*dynamodb.DynamoDB, error) {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION")),
	})
	if err != nil {
		fmt.Println(err)
	}

	return dynamodb.New(sess), err
}

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
		return db, err
	}

	err = db.Ping()
	if err != nil {
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
			fmt.Println("cant get db acccess")
			c.Status(500)
			c.Abort()
			return
		}

		defer db.Close()

		row := db.QueryRow(`SELECT email, salt, nonce, encrypted_key, pub_key, pub_key_enc_dec FROM users u
					JOIN verification_tokens vt ON vt.user_id = u.id
					WHERE token = $1
					AND expiration_date >= NOW()
					AND verified = TRUE`, (verificationToken))

		var email string
		var salt string
		var nonce string
		var encrypted_key string
		var public_key string
		var public_key_enc_dec string

		err = row.Scan(&email, &salt, &nonce, &encrypted_key, &public_key, &public_key_enc_dec)

		if err == sql.ErrNoRows {
			c.Status(401)
			c.Abort()
			return
		} else if err != nil {
			fmt.Println("some weird error,", err)
			c.Status(500)
			c.Abort()
			return
		}

		c.Set("email", email)
		c.Set("salt", salt)
		c.Set("nonce", nonce)
		c.Set("encrypted_key", encrypted_key)
		c.Set("public_key", public_key)
		c.Set("public_key_enc_dec", public_key_enc_dec)
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

	// If it reaches here then it was a success
	c.Status(200)
}

func signupUser(c *gin.Context) {

	type User struct {
		Email           string `json:"email"`
		Password        string `json:"password"`
		Salt            string `json:"salt"`
		Nonce           string `json:"nonce"`
		EncryptedKey    string `json:"encryptedKey"`
		PublicKey       string `json:"publicKey"`
		PublicKeyEncDec string `json:"publicKeyEncDec"`
	}

	fmt.Println("hihihi")
	var userReq User

	err := c.BindJSON(&userReq)

	if err != nil {
		c.Status(400) // Bad request from user
	}

	db, err := getDBAccess()

	if err != nil {
		fmt.Println("in here")
		c.Status(500) // Server issue on db
		return
	}

	hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(userReq.Password), 10)
	if err != nil {
		fmt.Println("over here")
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
			nonce,
			pub_key_enc_dec)  
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, userReq.Email, hashedPassword, userReq.PublicKey, userReq.EncryptedKey, userReq.Salt, userReq.Nonce, userReq.PublicKeyEncDec)
		if err != nil {
			fmt.Println(err)
			c.Status(500)
			return
		}

		// Setup s3 folder for user
		awsRegion := os.Getenv("AWS_REGION")
		s3Bucket := os.Getenv("S3_BUCKET")
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(awsRegion),
		})

		if err != nil {
			fmt.Println("Failed to create AWS session:", err)
			return
		}

		s3Client := s3.New(sess)
		_, err = s3Client.PutObject(&s3.PutObjectInput{
			Bucket: aws.String(s3Bucket),
			Key:    aws.String(fmt.Sprintf("user_data/%s/", userReq.Email)),
			Body:   nil,
		})

		if err != nil {
			fmt.Println("Failed to create S3 folder:", err)
			c.Status(500)
			return
		}

		c.Status(201)
		return
	} else if err != nil {
		fmt.Println("way over here")
		c.Status(500)
		return
	} else {
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
	var req SignatureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	email, exists := c.Get("email")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email not found in context"})
		return
	}

	db, err := getDBAccess()
	if err != nil {
		c.Status(500)
		return
	}

	var publicKey string
	emailStr, ok := email.(string)
	if !ok {
		c.Status(500)
		return
	}
	row := db.QueryRow("SELECT pub_key FROM users WHERE email = $1", emailStr)
	err = row.Scan(&publicKey)

	if err == sql.ErrNoRows {
		c.Status(404)
		return
	} else if err != nil {
		c.Status(500)
		return
	}

	// Decode public key from base64
	pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid public key format"})
		return
	}

	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse public key"})
		return
	}

	// Decode the signature from base64
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature encoding"})
		return
	}
	// Decode challenge from base64 to bytes
	challengeBytes, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid challenge encoding"})
		return
	}

	hashed := sha256.Sum256(challengeBytes)

	switch pk := pub.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, hashed[:], sigBytes)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Signature verification failed"})
			return
		}
	case *ecdsa.PublicKey:
		if len(sigBytes) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Empty signature"})
			return
		}
		if ecdsa.VerifyASN1(pk, hashed[:], sigBytes) {
			c.JSON(http.StatusOK, gin.H{"success": true})
			return
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Signature verification failed"})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported public key type"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func authorizeUser(c *gin.Context) {
	_, exists := c.Get("email")
	if !exists {
		c.Status(401)
		return
	}

	public_key_enc_dec, exists := c.Get("public_key_enc_dec")
	if !exists {
		c.Status(401)
		return
	}

	c.IndentedJSON(200, gin.H{"public_key_enc_dec": public_key_enc_dec})
}

func uploadUserData(c *gin.Context) {
	fmt.Println("we inside upload")

	// Define a struct for file metadata
	type FileMetadata struct {
		FullPath        string `json:"fullPath"`
		UploadDate      string `json:"uploadDate"`
		Iv              string `json:"iv"`
		EncryptedAesKey string `json:"encryptedAesKey"`
		EncryptedFile   string `json:"encryptedFile"`
		FileType        string `json:"fileType"`
	}

	var req struct {
		FileMetadata []FileMetadata `json:"file_metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	fileMetadatas := req.FileMetadata

	fmt.Println("fileMetadatas", fileMetadatas)

	emailVal, exists := c.Get("email")
	if !exists {
		c.Status(401)
		return
	}

	email, ok := emailVal.(string)
	if !ok {
		c.Status(500)
		return
	}

	db, err := initDynamoDB()
	if err != nil {
		fmt.Println("Failed to initialize DynamoDB:", err)
		c.Status(500)
		return
	}

	awsRegion := os.Getenv("AWS_REGION")
	s3Bucket := os.Getenv("S3_BUCKET")
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	})

	if err != nil {
		c.Status(500)
		return
	}

	s3Client := s3.New(sess)

	for i := 0; i < len(fileMetadatas); i++ {
		if !ok {
			c.Status(500)
			return
		}
		input := &dynamodb.GetItemInput{
			TableName: aws.String("file_metadata"),
			Key: map[string]*dynamodb.AttributeValue{
				"email":            {S: aws.String(email)},
				"originalFileName": {S: aws.String(fileMetadatas[i].FullPath)},
			},
			ProjectionExpression: aws.String("FileID"),
		}

		result, err := db.GetItem(input)
		if err != nil {
			fmt.Println("Error getting item from DynamoDB:", err)
			c.Status(500)
			return
		}

		//File already exists
		if result.Item != nil {
			originalPath := fileMetadatas[i].FullPath
			ext := filepath.Ext(originalPath)
			encPath := strings.TrimSuffix(originalPath, ext) + ".enc"

			_, err = s3Client.PutObject(&s3.PutObjectInput{
				Bucket:      aws.String(s3Bucket),
				Key:         aws.String(fmt.Sprintf("user_data/%s/%s", email, encPath)),
				Body:        bytes.NewReader([]byte(fileMetadatas[i].EncryptedFile)),
				ContentType: aws.String("application/octet-stream"),
			})

			if err != nil {
				c.Status(500)
				return
			}

			fmt.Printf("Updating item with email: %s, originalFileName: %s\n", email, fileMetadatas[i].FullPath)

			input := &dynamodb.UpdateItemInput{
				TableName: aws.String("file_metadata"),
				Key: map[string]*dynamodb.AttributeValue{
					"email":            {S: aws.String(email)},
					"originalFileName": {S: aws.String(fileMetadatas[i].FullPath)},
				},
				UpdateExpression: aws.String("SET lastModified = :lm, iv = :iv, EncryptedAesKey = :eak, FileType = :ft"),
				ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
					":lm":  {S: aws.String(fileMetadatas[i].UploadDate)},
					":iv":  {S: aws.String(fileMetadatas[i].Iv)},
					":eak": {S: aws.String(fileMetadatas[i].EncryptedAesKey)},
					":ft":  {S: aws.String(fileMetadatas[i].FileType)},
				},
			}

			_, err = db.UpdateItem(input)
			if err != nil {
				c.Status(500)
				return
			}
		} else {
			originalPath := fileMetadatas[i].FullPath
			ext := filepath.Ext(originalPath)
			encPath := strings.TrimSuffix(originalPath, ext) + ".enc"

			_, err = s3Client.PutObject(&s3.PutObjectInput{
				Bucket:      aws.String(s3Bucket),
				Key:         aws.String(fmt.Sprintf("user_data/%s/%s", email, encPath)),
				Body:        bytes.NewReader([]byte(fileMetadatas[i].EncryptedFile)),
				ContentType: aws.String("application/octet-stream"),
			})

			if err != nil {
				c.Status(500)
				return
			}

			input := &dynamodb.PutItemInput{
				TableName: aws.String("file_metadata"),
				Item: map[string]*dynamodb.AttributeValue{
					"email": {
						S: aws.String(email),
					},
					"lastModified": {
						S: aws.String(fileMetadatas[i].UploadDate),
					},
					"uploadDate": {
						S: aws.String(fileMetadatas[i].UploadDate),
					},
					"originalFileName": {
						S: aws.String(fileMetadatas[i].FullPath),
					},
					"iv": {
						S: aws.String(fileMetadatas[i].Iv),
					},
					"EncryptedAesKey": {
						S: aws.String(fileMetadatas[i].EncryptedAesKey),
					},
					"FileType": {
						S: aws.String(fileMetadatas[i].FileType),
					},
					"s3Path": {
						S: aws.String(fmt.Sprintf("user_data/%s/%s", email, encPath)),
					},
				},
			}

			_, err = db.PutItem(input)
			if err != nil {
				c.Status(500)
				return
			}
		}
	}

	c.Status(200)
}

func obtainUserFileNames(c *gin.Context) {
	email, exists := c.Get("email")
	if !exists {
		c.Status(401)
		return
	}

	db, err := initDynamoDB()

	if err != nil {
		c.Status(500)
	}

	emailStr, ok := email.(string)
	if !ok {
		c.Status(500)
		return
	}

	input := &dynamodb.QueryInput{
		TableName:              aws.String("file_metadata"),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":email": {S: aws.String(emailStr)},
		},
		ProjectionExpression: aws.String("originalFileName,lastModified"),
	}

	result, err := db.Query(input)
	if err != nil {
		fmt.Println("Error getting item from DynamoDB:", err)
		c.Status(500)
		return
	}
	fmt.Println(result)

	type fileDTO struct {
		FileName     string
		LastModified string
	}

	var files []fileDTO

	for _, item := range result.Items {
		fileNameAttr, ok1 := item["originalFileName"]
		lastModifiedAttr, ok2 := item["lastModified"]
		if ok1 && fileNameAttr.S != nil && ok2 && lastModifiedAttr.S != nil {
			fileObj := fileDTO{
				FileName:     *fileNameAttr.S,
				LastModified: *lastModifiedAttr.S,
			}
			files = append(files, fileObj)
		}
	}

	c.IndentedJSON(200, gin.H{"files": files})
}

func fetchUserFiles(c *gin.Context) {
	email, exists := c.Get("email")
	if !exists {
		c.Status(401)
		return
	}

	type Files struct {
		FileNameList []string `json:"selectedFiles"`
	}

	var filesReq Files

	err := c.BindJSON(&filesReq)

	fmt.Println(filesReq)

	if err != nil {
		c.Status(400)
		return
	}

	if len(filesReq.FileNameList) == 0 {
		c.Status(400)
		return
	}

	db, err := initDynamoDB()

	if err != nil {
		c.Status(500)
		return
	}

	emailStr, ok := email.(string)
	if !ok {
		c.Status(500)
		return
	}

	if len(filesReq.FileNameList) > 100 {
		type fileDTO struct {
			FileName        string
			EncryptedFile   string
			FileType        string
			Iv              string
			EncryptedAesKey string
		}

		var files []fileDTO
		remainder := len(filesReq.FileNameList) % 100
		groups := (len(filesReq.FileNameList) / 100)

		if remainder != 0 {
			groups += 1
		}

		awsRegion := os.Getenv("AWS_REGION")
		s3Bucket := os.Getenv("S3_BUCKET")
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(awsRegion),
		})

		if err != nil {
			c.Status(500)
			return
		}

		s3Client := s3.New(sess)

		for i := 0; i < groups; i++ {
			start := i * 100
			end := start + 100

			if end > len(filesReq.FileNameList) {
				end = len(filesReq.FileNameList)
			}
			var keys []map[string]*dynamodb.AttributeValue
			for _, fileName := range filesReq.FileNameList[start:end] {
				keys = append(keys, map[string]*dynamodb.AttributeValue{
					"email":            {S: aws.String(emailStr)},
					"originalFileName": {S: aws.String(fileName)},
				})
			}

			input := &dynamodb.BatchGetItemInput{
				RequestItems: map[string]*dynamodb.KeysAndAttributes{
					"file_metadata": {
						Keys:                 keys,
						ProjectionExpression: aws.String("originalFileName, s3Path, FileType, EncryptedAesKey, iv"),
					},
				},
			}

			result, err := db.BatchGetItem(input)
			if err != nil {
				fmt.Println("Error getting item from DynamoDB:", err)
				c.Status(500)
				return
			}
			fmt.Println(result)

			for _, items := range result.Responses {
				for _, item := range items {
					fileNameAttr, ok1 := item["originalFileName"]
					s3PathAttr, ok2 := item["s3Path"]
					fileTypeAttr, ok3 := item["FileType"]
					ivAttr, ok4 := item["iv"]
					encryptedAesKeyAttr, ok5 := item["EncryptedAesKey"]
					if ok1 && fileNameAttr.S != nil && ok2 && s3PathAttr.S != nil && ok3 && fileTypeAttr.S != nil && ok4 && ivAttr.S != nil && ok5 && encryptedAesKeyAttr.S != nil {
						input := &s3.GetObjectInput{
							Bucket: aws.String(s3Bucket),
							Key:    aws.String(*s3PathAttr.S),
						}

						result, err := s3Client.GetObject(input)
						if err != nil {
							// handle error
							log.Fatalf("Failed to get object: %v", err)
						}
						defer result.Body.Close()

						// Read the object data
						data, err := io.ReadAll(result.Body)
						if err != nil {
							// handle error
							log.Fatalf("Failed to read object data: %v", err)
						}

						strFile := string(data)

						fileObj := fileDTO{
							FileName:        *fileNameAttr.S,
							FileType:        *fileTypeAttr.S,
							EncryptedFile:   strFile,
							Iv:              *ivAttr.S,
							EncryptedAesKey: *encryptedAesKeyAttr.S,
						}
						files = append(files, fileObj)
					}
				}
			}
		}

		c.IndentedJSON(200, gin.H{"files": files})
	} else {
		var keys []map[string]*dynamodb.AttributeValue
		for _, fileName := range filesReq.FileNameList {
			keys = append(keys, map[string]*dynamodb.AttributeValue{
				"email":            {S: aws.String(emailStr)},
				"originalFileName": {S: aws.String(fileName)},
			})
		}

		input := &dynamodb.BatchGetItemInput{
			RequestItems: map[string]*dynamodb.KeysAndAttributes{
				"file_metadata": {
					Keys:                 keys,
					ProjectionExpression: aws.String("originalFileName, s3Path, FileType, iv, EncryptedAesKey"),
				},
			},
		}

		result, err := db.BatchGetItem(input)
		if err != nil {
			fmt.Println("Error getting item from DynamoDB:", err)
			c.Status(500)
			return
		}
		fmt.Println(result)

		type fileDTO struct {
			FileName        string
			EncryptedFile   string
			FileType        string
			Iv              string
			EncryptedAesKey string
		}

		var files []fileDTO

		awsRegion := os.Getenv("AWS_REGION")
		s3Bucket := os.Getenv("S3_BUCKET")
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(awsRegion),
		})

		if err != nil {
			fmt.Println("Failed to create AWS session:", err)
			return
		}

		s3Client := s3.New(sess)

		for _, items := range result.Responses {
			for _, item := range items {
				fileNameAttr, ok1 := item["originalFileName"]
				s3PathAttr, ok2 := item["s3Path"]
				fileTypeAttr, ok3 := item["FileType"]
				ivAttr, ok4 := item["iv"]
				encryptedAesKeyAttr, ok5 := item["EncryptedAesKey"]
				if ok1 && fileNameAttr.S != nil && ok2 && s3PathAttr.S != nil && ok3 && fileTypeAttr.S != nil && ok4 && ivAttr.S != nil && ok5 && encryptedAesKeyAttr.S != nil {
					input := &s3.GetObjectInput{
						Bucket: aws.String(s3Bucket),
						Key:    aws.String(*s3PathAttr.S),
					}

					result, err := s3Client.GetObject(input)
					if err != nil {
						// handle error
						log.Fatalf("Failed to get object: %v", err)
					}
					defer result.Body.Close()

					// Read the object data
					data, err := io.ReadAll(result.Body)
					if err != nil {
						// handle error
						log.Fatalf("Failed to read object data: %v", err)
					}

					strFile := string(data)

					fileObj := fileDTO{
						FileName:        *fileNameAttr.S,
						FileType:        *fileTypeAttr.S,
						EncryptedFile:   strFile,
						Iv:              *ivAttr.S,
						EncryptedAesKey: *encryptedAesKeyAttr.S,
					}
					files = append(files, fileObj)
				}
			}
		}

		c.IndentedJSON(200, gin.H{"files": files})
	}
}

func deleteUserFiles(c *gin.Context) {
	email, exists := c.Get("email")
	if !exists {
		c.Status(401)
		return
	}

	type Files struct {
		FileNameList []string `json:"selectedFiles"`
	}

	var filesReq Files

	err := c.BindJSON(&filesReq)

	fmt.Println(filesReq)

	if err != nil {
		c.Status(400)
		return
	}

	if len(filesReq.FileNameList) == 0 {
		c.Status(400)
		return
	}

	db, err := initDynamoDB()

	if err != nil {
		c.Status(500)
		return
	}

	emailStr, ok := email.(string)
	if !ok {
		c.Status(500)
		return
	}

	awsRegion := os.Getenv("AWS_REGION")
	s3Bucket := os.Getenv("S3_BUCKET")
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	})

	if err != nil {
		c.Status(500)
		return
	}

	s3Client := s3.New(sess)

	var files []string

	if len(filesReq.FileNameList) > 25 {
		remainder := len(filesReq.FileNameList) % 25
		groups := (len(filesReq.FileNameList) / 25)

		if remainder != 0 {
			groups += 1
		}

		for i := 0; i < groups; i++ {
			start := i * 25
			end := start + 25

			if end > len(filesReq.FileNameList) {
				end = len(filesReq.FileNameList)
			}
			var keys []map[string]*dynamodb.AttributeValue
			for _, fileName := range filesReq.FileNameList[start:end] {
				keys = append(keys, map[string]*dynamodb.AttributeValue{
					"email":            {S: aws.String(emailStr)},
					"originalFileName": {S: aws.String(fileName)},
				})
			}

			input := &dynamodb.BatchGetItemInput{
				RequestItems: map[string]*dynamodb.KeysAndAttributes{
					"file_metadata": {
						Keys:                 keys,
						ProjectionExpression: aws.String("originalFileName, s3Path"),
					},
				},
			}

			result, err := db.BatchGetItem(input)
			if err != nil {
				fmt.Println("Error getting item from DynamoDB:", err)
				c.Status(500)
				return
			}

			writeRequests := make([]*dynamodb.WriteRequest, len(keys))
			for i, key := range keys {
				writeRequests[i] = &dynamodb.WriteRequest{
					DeleteRequest: &dynamodb.DeleteRequest{
						Key: key,
					},
				}
			}

			deleteInput := &dynamodb.BatchWriteItemInput{
				RequestItems: map[string][]*dynamodb.WriteRequest{
					"file_metadata": writeRequests,
				},
			}

			_, err = db.BatchWriteItem(deleteInput)
			if err != nil {
				c.Status(500)
				return
			}

			for _, items := range result.Responses {
				for _, item := range items {
					s3PathAttr, ok := item["s3Path"]
					originalFileNameAttr, ok2 := item["originalFileName"]
					if ok && s3PathAttr.S != nil && ok2 && originalFileNameAttr.S != nil {
						input := &s3.DeleteObjectInput{
							Bucket: aws.String(s3Bucket),
							Key:    aws.String(*s3PathAttr.S),
						}

						_, err := s3Client.DeleteObject(input)
						if err != nil {
							c.Status(500)
							return
						}

						files = append(files, *originalFileNameAttr.S)
					}
				}
			}
		}
		c.IndentedJSON(200, gin.H{"files": files})
	} else {
		var keys []map[string]*dynamodb.AttributeValue
		for _, fileName := range filesReq.FileNameList {
			keys = append(keys, map[string]*dynamodb.AttributeValue{
				"email":            {S: aws.String(emailStr)},
				"originalFileName": {S: aws.String(fileName)},
			})
		}

		input := &dynamodb.BatchGetItemInput{
			RequestItems: map[string]*dynamodb.KeysAndAttributes{
				"file_metadata": {
					Keys:                 keys,
					ProjectionExpression: aws.String("originalFileName, s3Path"),
				},
			},
		}

		result, err := db.BatchGetItem(input)
		if err != nil {
			fmt.Println("Error getting item from DynamoDB:", err)
			c.Status(500)
			return
		}

		writeRequests := make([]*dynamodb.WriteRequest, len(keys))
		for i, key := range keys {
			writeRequests[i] = &dynamodb.WriteRequest{
				DeleteRequest: &dynamodb.DeleteRequest{
					Key: key,
				},
			}
		}

		deleteInput := &dynamodb.BatchWriteItemInput{
			RequestItems: map[string][]*dynamodb.WriteRequest{
				"file_metadata": writeRequests,
			},
		}

		_, err = db.BatchWriteItem(deleteInput)
		if err != nil {
			c.Status(500)
			return
		}

		for _, items := range result.Responses {
			for _, item := range items {
				originalFileNameAttr, ok1 := item["originalFileName"]
				s3PathAttr, ok2 := item["s3Path"]
				if ok1 && originalFileNameAttr.S != nil && ok2 && s3PathAttr.S != nil {
					input := &s3.DeleteObjectInput{
						Bucket: aws.String(s3Bucket),
						Key:    aws.String(*s3PathAttr.S),
					}

					_, err := s3Client.DeleteObject(input)
					if err != nil {
						c.Status(500)
						return
					}
					files = append(files, *originalFileNameAttr.S)
				}
			}
		}
		c.IndentedJSON(200, gin.H{"files": files})
	}
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
	router.GET("/users/authorize", AuthMiddleware(), authorizeUser)
	router.POST("/users/upload", AuthMiddleware(), uploadUserData)
	router.GET("/users/files", AuthMiddleware(), obtainUserFileNames)
	router.POST("/users/files", AuthMiddleware(), fetchUserFiles)
	router.DELETE("/users/files", AuthMiddleware(), deleteUserFiles)
	router.Run("localhost:8080")
}
