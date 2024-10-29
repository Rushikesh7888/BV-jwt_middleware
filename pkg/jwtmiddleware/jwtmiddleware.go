package jwtmiddleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"

	decrypt "github.com/Rushikesh7888/BV-auth_Service/pkg/helper/encryption"
	userModel "github.com/Rushikesh7888/BV-individual_verification_form/pkg/models"
	"github.com/Rushikesh7888/BV-jwt_middleware/pkg/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func JWTMiddleware(db *mongo.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the Authorization header
		authHeader := c.GetHeader("Authorization")

		// Check if Authorization header is empty
		if authHeader == "" {
			authHeader = c.Query("Authorization") // Check URL query parameter
		}

		cfg, err := config.Env()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load config"})
			c.Abort()
			return
		}

		// Parse the JWT token
		token, err := jwt.Parse(authHeader, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				logrus.Error("Error parsing token: ", err) // Log the error
				return nil, fmt.Errorf("invalid signing method")
			}
			return []byte(cfg.JWT.Secret), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header"})
			c.Abort()
			return
		}

		// Extract userID from claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			contactNumber, exists := claims["contactNo"]
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "contact not found in claims"})
				c.Abort()
				return
			}

			// Type assertion to convert contactNumber to string
			ContactNoToString, ok := contactNumber.(string)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid contact number in claims"})
				c.Abort()
				return
			}

			// decrypt the contact no
			decryptedContactNo, err := decrypt.DecryptWithFixedKeyNonce(ContactNoToString)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error decrypting contact number"})
				c.Abort()
				return
			}

			// convert the string to int64
			contact, err := StringToInt64(decryptedContactNo)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error converting contact number"})
				c.Abort()
				return
			}

			// check the user is in userprofile model or not
			filter := bson.M{"contactno": contact}
			var existingUser userModel.UserProfile
			err = db.Collection("userprofile").FindOne(context.Background(), filter).Decode(&existingUser)

			if err == nil {
				// User found, get the user details
				user, err := GetUserByContactNo(contact, db)
				if err != nil {
					c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to get user: %v", err))
					return
				}

				// Set the "user" value in the context
				c.Set("user", user)

				// Continue handling the request
				c.Next()
				return
			}

			// User not found, create a new record in userprofile
			newUser := userModel.UserProfile{
				ContactNo: contact,
			}
			_, err = db.Collection("userprofile").InsertOne(context.Background(), newUser)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create new user"})
				return
			}

			log.Printf("Global Contact No: %v", contact)

			// Get the updated user details
			user, err := GetUserByContactNo(contact, db)
			if err != nil {
				c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to get user: %v", err))
				return
			}

			// Set the "user" value in the context
			c.Set("user", user)

			// Continue handling the request
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header"})
			c.Abort()
		}
	}
}

// fetch user by contact number
func GetUserByContactNo(contactNo int64, db *mongo.Database) (*userModel.UserProfile, error) {
	var user userModel.UserProfile

	// Create a filter for the query
	filter := bson.M{"contactno": contactNo}

	// Find the user in the MongoDB collection
	err := db.Collection("userprofile").FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		// handle error
		return nil, err
	}

	return &user, nil
}

// Insert the user into users database
func UpdateContactNoInUserProfile(c *gin.Context, db *mongo.Database, EncryptedContactNo string) error {

	// decrypt the contact no
	decryptedContactNo, err := decrypt.DecryptWithFixedKeyNonce(EncryptedContactNo)
	if err != nil {
		return err
	}

	// convert string to int64
	number, err := StringToInt64(decryptedContactNo)
	if err != nil {
		fmt.Printf("Error converting string to int64: %v\n", err)
		return err
	}

	// Insert data into user model
	updateUser := userModel.UserProfile{
		ContactNo: number,
	}

	userCollection := db.Collection("userprofile")

	_, err = userCollection.InsertOne(context.Background(), updateUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save otp details"})
		return err
	}

	return nil
}

// StringToInt64 converts a string to an int64
func StringToInt64(s string) (int64, error) {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return i, nil
}
