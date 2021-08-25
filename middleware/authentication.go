package middleware

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/twinj/uuid"
	"gitlab.com/kitalabs/go-2gaijin/config"
	"gitlab.com/kitalabs/go-2gaijin/models"
	"gitlab.com/kitalabs/go-2gaijin/responses"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	var user models.User
	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &user)
	var res responses.ResponseMessage
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if user.Email == "" || user.Password == "" {
		res.Status = "Error"
		res.Message = "Invalid credentials"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if user.FirstName == "" {
		res.Status = "Error"
		res.Message = "First name must not be empty"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	collection := DB.Collection("users")

	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
	var result models.User
	err = collection.FindOne(context.TODO(), bson.D{{"email", user.Email}}).Decode(&result)

	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)

			if err != nil {
				res.Status = "Error"
				res.Message = "Error While Hashing Password, Try Again"
				json.NewEncoder(c.Writer).Encode(res)
				return
			}
			user.ID = primitive.NewObjectIDFromTimestamp(time.Now())
			user.Password = string(hash)
			user.CreatedAt = primitive.NewDateTimeFromTime(time.Now())
			user.UpdatedAt = primitive.NewDateTimeFromTime(time.Now())
			user.NotifRead = true
			user.MessageRead = true

			_, err = collection.InsertOne(context.TODO(), user)
			if err != nil {
				res.Status = "Error"
				res.Message = "Error While Creating User, Try Again"
				json.NewEncoder(c.Writer).Encode(res)
				return
			}

			tokenString, err := GenerateNewToken(user)
			/*update := bson.M{"$set": bson.M{"token": tokenString}}
			_, err = collection.UpdateOne(context.Background(), bson.D{{"email", user.Email}}, update)*/
			if err != nil {
				res.Status = "Error"
				res.Message = "Error while generating token, try again"
				json.NewEncoder(c.Writer).Encode(res)
				return
			}

			user.Token = tokenString.AuthToken
			user.RefreshToken = tokenString.RefreshToken
			user.AuthTokenExpiry = tokenString.AuthTokenExpiry
			user.RefreshTokenExpiry = tokenString.RefreshTokenExpiry
			user.Password = ""

			var userData responses.UserData
			userData.User = user

			var res responses.GenericResponse

			var paymentMethod models.PaymentMethod
			paymentMethod.ID = primitive.NewObjectIDFromTimestamp(time.Now())
			_, err = DB.Collection("payment_methods").InsertOne(context.Background(), paymentMethod)
			if err != nil {
				res.Status = "Error"
				res.Message = "Error while inserting payment methods, try again"
				json.NewEncoder(c.Writer).Encode(res)
				return
			}

			res.Status = "Success"
			res.Message = "Registration successful"
			res.Data = userData

			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	res.Status = "Error"
	res.Message = "Email already exists"
	json.NewEncoder(c.Writer).Encode(res)
	return
}

func LoginHandler(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	var user models.User
	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
	}

	collection := DB.Collection("users")

	if err != nil {
		log.Fatal(err)
	}
	var result models.User
	var res responses.ResponseMessage
	var options = &options.FindOptions{}
	options.SetProjection(bson.M{
		"_id":        1,
		"first_name": 1,
		"last_name":  1,
		"avatar":     1,
		"token":      1,
	})

	if user.Email == "" || user.Password == "" {
		res.Status = "Error"
		res.Message = "Invalid credentials"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	err = collection.FindOne(context.TODO(), bson.D{{"email", user.Email}}).Decode(&result)

	if err != nil {
		res.Status = "Error"
		res.Message = "Invalid email"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))

	if err != nil {
		res.Status = "Error"
		res.Message = "Invalid password"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	tokenString, err := GenerateNewToken(result)
	if err != nil {
		res.Status = "Error"
		res.Message = "Error while generating token, try again"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	result.Token = tokenString.AuthToken
	result.RefreshToken = tokenString.RefreshToken
	result.AuthTokenExpiry = tokenString.AuthTokenExpiry
	result.RefreshTokenExpiry = tokenString.RefreshTokenExpiry
	result.Password = ""

	if result.AvatarURL != "" {
		if !strings.HasPrefix(result.AvatarURL, "https://") {
			result.AvatarURL = AvatarURLPrefix + result.ID.Hex() + "/" + result.AvatarURL
		}
	}

	var userData responses.UserData
	userData.User = result

	var resp responses.GenericResponse

	resp.Status = "Success"
	resp.Message = "Login Successful"
	resp.Data = userData
	json.NewEncoder(c.Writer).Encode(resp)
}

func ProfileHandler(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	tokenString := c.Request.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte(os.Getenv("MY_JWT_TOKEN")), nil
	})
	var result models.User
	var tmpUser models.User
	var res responses.ResponseMessage
	var profileData responses.ProfileData

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		id, err := primitive.ObjectIDFromHex(claims["_id"].(string))

		err = DB.Collection("users").FindOne(context.Background(), bson.M{"_id": id}).Decode(&tmpUser)
		if err != nil {
			res.Status = "Error"
			res.Message = "Something went wrong. Please try again"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		AtUUID := claims["at_uuid"].(string)
		var collection = DB.Collection("tokens")
		var tokenDetail models.Token
		err = collection.FindOne(context.Background(), bson.M{"auth_token_uuid": AtUUID}).Decode(&tokenDetail)
		if err != nil {
			res.Status = "Error"
			res.Message = "Unauthorized"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		AtExpiry, _ := time.Parse(time.RFC3339, claims["at_expiry"].(string))
		if time.Now().After(AtExpiry) {
			res.Status = "Error"
			res.Message = "Token Expired"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var wg sync.WaitGroup

		// Search Gold Trust Coins
		wg.Add(1)
		go func() {
			filter := bson.D{bson.E{"receiver_id", id}, bson.E{"type", "gold"}}
			result.GoldCoin, err = DB.Collection("trust_coins").CountDocuments(context.Background(), filter)
			wg.Done()
		}()

		// Search Silver Trust Coins
		wg.Add(1)
		go func() {
			filter := bson.D{bson.E{"receiver_id", id}, bson.E{"type", "silver"}}
			result.SilverCoin, err = DB.Collection("trust_coins").CountDocuments(context.Background(), filter)
			wg.Done()
		}()
		wg.Wait()

		result.ID = id
		result.Email = tmpUser.Email
		result.Phone = tmpUser.Phone
		result.FirstName = tmpUser.FirstName
		result.LastName = tmpUser.LastName
		result.AvatarURL = ""
		if tmpUser.AvatarURL != "" {
			if !strings.HasPrefix(tmpUser.AvatarURL, "https://") {
				result.AvatarURL = AvatarURLPrefix + claims["_id"].(string) + "/" + tmpUser.AvatarURL
			} else {
				result.AvatarURL = tmpUser.AvatarURL
			}
		}
		result.Role = tmpUser.Role
		result.DateOfBirth = tmpUser.DateOfBirth
		result.ShortBio = tmpUser.ShortBio
		result.Subscription = tmpUser.Subscription
		result.SubsExpiryDate = tmpUser.SubsExpiryDate
		result.IsSubscribed = IsUserSubscribed(tmpUser.ID)

		var options = &options.FindOptions{}
		projection := bson.D{{"_id", 1}, {"name", 1}, {"price", 1}, {"img_url", 1}, {"user_id", 1}, {"seller_name", 1}, {"latitude", 1}, {"longitude", 1}, {"status_cd", 1}}
		sort := bson.D{{"created_at", -1}}
		options.SetProjection(projection)
		options.SetSort(sort)
		filter := bson.D{{"user_id", id}}

		profileData.Profile = result
		profileData.PostedItems = PopulateProductsWithAnImage(filter, options)

		var resp responses.GenericResponse
		paymentMethod, err := GetPaymentMethod(profileData.Profile.ID.Hex())
		if err != nil {
			resp.Status = "Error"
			resp.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(resp)
			return
		}
		profileData.PaymentMethod = paymentMethod

		resp.Status = "Success"
		resp.Message = "Profile Successfully Retrieved"
		resp.Data = profileData

		json.NewEncoder(c.Writer).Encode(resp)
		return
	} else {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
}

func UpdateProfile(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	tokenString := c.Request.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte(os.Getenv("MY_JWT_TOKEN")), nil
	})
	var res responses.ResponseMessage

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		id, err := primitive.ObjectIDFromHex(claims["_id"].(string))

		if err != nil {
			res.Status = "Error"
			res.Message = "Something went wrong. Please try again"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		AtUUID := claims["at_uuid"].(string)
		var collection = DB.Collection("tokens")
		var tokenDetail models.Token
		err = collection.FindOne(context.Background(), bson.M{"auth_token_uuid": AtUUID}).Decode(&tokenDetail)
		if err != nil {
			res.Status = "Error"
			res.Message = "Unauthorized"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		AtExpiry, _ := time.Parse(time.RFC3339, claims["at_expiry"].(string))
		if time.Now().After(AtExpiry) {
			res.Status = "Error"
			res.Message = "Token Expired"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var user models.User
		body, _ := ioutil.ReadAll(c.Request.Body)
		err = json.Unmarshal(body, &user)
		var res responses.ResponseMessage
		if err != nil {
			res.Status = "Error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		if user.Email == "" || user.FirstName == "" {
			res.Status = "Error"
			res.Message = "Email/First Name Info Should not be Empty"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var filter = bson.M{"_id": id}
		var update = bson.M{}
		if user.Email != claims["email"].(string) && user.Phone != claims["phone"].(string) {
			update = bson.M{"$set": bson.M{"first_name": user.FirstName, "last_name": user.LastName, "phone_confirmed": false,
				"email": user.Email, "date_of_birth": user.DateOfBirth, "phone": user.Phone, "short_bio": user.ShortBio, "email_confirmed": false}}
		} else if user.Email != claims["email"].(string) && user.Phone == claims["phone"].(string) {
			update = bson.M{"$set": bson.M{"first_name": user.FirstName, "last_name": user.LastName,
				"email": user.Email, "date_of_birth": user.DateOfBirth, "phone": user.Phone, "short_bio": user.ShortBio, "email_confirmed": false}}
		} else if user.Email == claims["email"].(string) && user.Phone != claims["phone"].(string) {
			update = bson.M{"$set": bson.M{"first_name": user.FirstName, "last_name": user.LastName, "phone_confirmed": false,
				"email": user.Email, "date_of_birth": user.DateOfBirth, "phone": user.Phone, "short_bio": user.ShortBio}}
		} else {
			update = bson.M{"$set": bson.M{"first_name": user.FirstName, "last_name": user.LastName,
				"email": user.Email, "date_of_birth": user.DateOfBirth, "phone": user.Phone, "short_bio": user.ShortBio}}
		}

		collection = DB.Collection("users")
		_, err = collection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			res.Status = "Error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var newProfile models.User
		err = collection.FindOne(context.Background(), filter).Decode(&newProfile)
		if err != nil {
			res.Status = "Error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"_id":            id,
			"email":          user.Email,
			"phone":          user.Phone,
			"first_name":     user.FirstName,
			"last_name":      user.LastName,
			"avatar":         claims["avatar"].(string),
			"role":           claims["role"].(string),
			"last_active_at": primitive.NewDateTimeFromTime(time.Now()),
			"at_expiry":      primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15)),
			"at_uuid":        AtUUID,
		})
		authTokenString, err := authToken.SignedString([]byte(os.Getenv("MY_JWT_TOKEN")))

		update = bson.M{"$set": bson.M{"auth_token": authTokenString, "auth_token_expiry": primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15))}}
		_, err = collection.UpdateOne(context.Background(), bson.D{{"auth_token_uuid", AtUUID}}, update)
		if err != nil {
			res.Status = "Error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}
		user.Token = authTokenString
		if claims["avatar"].(string) != "" {
			user.AvatarURL = AvatarURLPrefix + id.Hex() + "/" + claims["avatar"].(string)
		}

		var resp responses.GenericResponse
		resp.Status = "Success"
		resp.Message = "Profile Successfully Updated"
		resp.Data = user

		json.NewEncoder(c.Writer).Encode(resp)
		return
	}

	res.Status = "Error"
	res.Message = err.Error()
	json.NewEncoder(c.Writer).Encode(res)
	return
}

func LogoutHandler(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	tokenString := c.Request.Header.Get("Authorization")
	var res responses.ResponseMessage
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte(os.Getenv("MY_JWT_TOKEN")), nil
	})
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if err != nil {
			res.Status = "Error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		AtExpiry, _ := time.Parse(time.RFC3339, claims["at_expiry"].(string))
		if time.Now().After(AtExpiry) {
			res.Status = "Error"
			res.Message = "Unauthorized"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var AtUUID = claims["at_uuid"].(string)
		var collection = DB.Collection("tokens")
		collection.FindOneAndDelete(context.Background(), bson.M{"auth_token_uuid": AtUUID})
	} else {
		res.Status = "Error"
		res.Message = "Unauthorized"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
	res.Status = "Success"
	res.Message = "You have been logged out successfully"
	json.NewEncoder(c.Writer).Encode(res)
	return
}

func LoggedInUser(tokenString string) (models.User, bool) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte(os.Getenv("MY_JWT_TOKEN")), nil
	})

	var result models.User

	if err != nil {
		return result, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		id, err := primitive.ObjectIDFromHex(claims["_id"].(string))
		if err != nil {
			return result, false
		}

		AtUUID := claims["at_uuid"].(string)
		var collection = DB.Collection("tokens")
		var tokenDetail models.Token
		err = collection.FindOne(context.Background(), bson.M{"auth_token_uuid": AtUUID}).Decode(&tokenDetail)
		if err != nil {
			return result, false
		}

		AtExpiry, _ := time.Parse(time.RFC3339, claims["at_expiry"].(string))
		if time.Now().After(AtExpiry) {
			return result, false
		}

		result.ID = id
		result.Email = claims["email"].(string)
		result.FirstName = claims["first_name"].(string)
		result.LastName = claims["last_name"].(string)
		result.AvatarURL = ""
		if claims["avatar"].(string) != "" {
			result.AvatarURL = AvatarURLPrefix + claims["_id"].(string) + "/" + claims["avatar"].(string)
		}
		result.Role = claims["role"].(string)
	} else {
		return result, false
	}

	return result, true
}

func RefreshToken(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	tokenString := c.Request.Header.Get("Authorization")
	var res responses.ResponseMessage
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte(os.Getenv("MY_JWT_TOKEN")), nil
	})

	var tokenDetail models.Token

	if err != nil {
		res.Status = "Error"
		res.Message = "Something went wrong. Please try again"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		id, err := primitive.ObjectIDFromHex(claims["_id"].(string))
		if err != nil {
			res.Status = "Error"
			res.Message = "Something went wrong. Please try again"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		RtExpiry, _ := time.Parse(time.RFC3339, claims["rt_expiry"].(string))
		if time.Now().After(RtExpiry) {
			res.Status = "Error"
			res.Message = "Token Expired"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		RtUUID := claims["rt_uuid"].(string)
		var collection = DB.Collection("tokens")
		err = collection.FindOne(context.Background(), bson.M{"refresh_token_uuid": RtUUID}).Decode(&tokenDetail)
		if err != nil {
			res.Status = "Error"
			res.Message = "Unauthorized"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"_id":            id,
			"phone":          claims["phone"].(string),
			"email":          claims["email"].(string),
			"first_name":     claims["first_name"].(string),
			"last_name":      claims["last_name"].(string),
			"avatar":         claims["avatar"].(string),
			"role":           claims["role"].(string),
			"last_active_at": primitive.NewDateTimeFromTime(time.Now()),
			"at_expiry":      primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15)),
			"at_uuid":        tokenDetail.AuthTokenUUID,
		})
		authTokenString, err := authToken.SignedString([]byte(os.Getenv("MY_JWT_TOKEN")))

		update := bson.M{"$set": bson.M{"auth_token": authTokenString, "auth_token_expiry": primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15))}}
		_, err = collection.UpdateOne(context.Background(), bson.D{{"refresh_token_uuid", RtUUID}}, update)
		if err != nil {
			res.Status = "Error"
			res.Message = "Something went wrong"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}
		tokenDetail.AuthToken = authTokenString
		tokenDetail.AuthTokenExpiry = primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15))
	} else {
		res.Status = "Error"
		res.Message = "Token Expired"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	var resp responses.GenericResponse
	var tokenData responses.TokenData
	tokenData.Token = tokenDetail

	resp.Status = "Success"
	resp.Message = "Token Refreshed"
	resp.Data = tokenData
	json.NewEncoder(c.Writer).Encode(resp)
	return
}

func ResetPasswordHandler(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")

	resetInfo := struct {
		Email  string `json:"email"`
		Source string `json:"source"`
	}{}

	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &resetInfo)
	var res responses.GenericResponse
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	var collection = DB.Collection("users")

	var result models.User
	err = collection.FindOne(context.Background(), bson.D{{"email", resetInfo.Email}}).Decode(&result)
	if err != nil {
		res.Status = "Error"
		res.Message = "Email not found"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	tokenString, err := generateResetToken(result)
	if err != nil {
		res.Status = "Error"
		res.Message = "Something went wrong. Try again"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	tokenExpiry := primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 1))
	update := bson.M{"$set": bson.M{"reset_password_token": tokenString, "reset_token_expiry": tokenExpiry}}

	_, err = collection.UpdateOne(context.Background(), bson.D{{"email", resetInfo.Email}}, update)
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	res.Status = "Success"
	res.Message = "Check your email to reset your password"
	SendResetPasswordEmail(tokenString, resetInfo.Email, resetInfo.Source)

	json.NewEncoder(c.Writer).Encode(res)
	return
}

func UpdatePasswordHandler(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	var user models.User
	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &user)
	var res responses.ResponseMessage
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	var collection = DB.Collection("users")

	var result models.User
	err = collection.FindOne(context.Background(), bson.D{{"email", user.Email}}).Decode(&result)
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if result.ResetPasswordToken != "" && user.ResetPasswordToken != "" {
		if result.ResetPasswordToken == user.ResetPasswordToken {
			expiryTime := result.ResetTokenExpiry.Time()

			if time.Now().Before(expiryTime) {
				hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)
				if err != nil {
					res.Status = "Error"
					res.Message = "Error While Hashing Password, Try Again"
					json.NewEncoder(c.Writer).Encode(res)
					return
				}
				update := bson.M{"$set": bson.M{"password": string(hash)}}

				_, err = collection.UpdateOne(context.Background(), bson.D{{"email", user.Email}}, update)
				if err != nil {
					res.Status = "Error"
					res.Message = err.Error()
					json.NewEncoder(c.Writer).Encode(res)
					return
				}

				update = bson.M{"$set": bson.M{"reset_password_token": "", "reset_token_expiry": primitive.NewDateTimeFromTime(time.Now())}}
				_, err = collection.UpdateOne(context.Background(), bson.D{{"email", user.Email}}, update)
				if err != nil {
					res.Status = "Error"
					res.Message = err.Error()
					json.NewEncoder(c.Writer).Encode(res)
					return
				}

				res.Status = "Success"
				res.Message = "Password Successfully Changed"
				json.NewEncoder(c.Writer).Encode(res)
				return
			} else {
				res.Status = "Error"
				res.Message = "Session has expired. Try again"
				json.NewEncoder(c.Writer).Encode(res)
				return
			}
		} else {
			res.Status = "Error"
			res.Message = "Wrong credentials. Try again"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}
	} else {
		res.Status = "Error"
		res.Message = "Something went wrong. Try again"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
}

func IsUserSubscribed(id primitive.ObjectID) bool {
	var user models.User

	var collection = DB.Collection("users")
	err := collection.FindOne(context.Background(), bson.M{"_id": id}).Decode(&user)
	if err != nil {
		log.Fatal(err)
	}

	if user.Subscription == "basic" || user.Subscription == "full" {
		if time.Now().After(user.SubsExpiryDate.Time()) {
			return false
		}
		return true
	}
	return false
}

func GetSubscriptionStatus(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")

	var res responses.GenericResponse
	subscriptionStatus := struct {
		IsSubscribed bool `json:"is_subscribed"`
	}{}

	tokenString := c.Request.Header.Get("Authorization")
	userData, isLoggedIn := LoggedInUser(tokenString)
	if isLoggedIn {
		var subsStatus bool
		subsStatus = IsUserSubscribed(userData.ID)
		subscriptionStatus.IsSubscribed = subsStatus

		res.Status = "Success"
		res.Message = "Subscription Status Retrieved"
		res.Data = subscriptionStatus
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
	res.Status = "Error"
	res.Message = "Unauthorized"
	json.NewEncoder(c.Writer).Encode(res)
	return
}

func EmailConfirmation(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")

	var res responses.ResponseMessage
	var err error

	email := c.Request.URL.Query().Get("email")
	token := c.Request.URL.Query().Get("confirm_token")

	var collection = DB.Collection("users")

	var result models.User
	err = collection.FindOne(context.Background(), bson.D{{"email", email}}).Decode(&result)
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if result.ConfirmToken != "" && token != "" {
		if result.ConfirmToken == token {
			expiryTime := result.ConfirmTokenExpiry.Time()

			if time.Now().Before(expiryTime) {
				update := bson.M{"$set": bson.M{"email_confirmed": true, "confirm_token": "", "confirm_token_expiry": primitive.NewDateTimeFromTime(time.Now())}}
				_, err = collection.UpdateOne(context.Background(), bson.D{{"email", email}}, update)
				if err != nil {
					res.Status = "Error"
					res.Message = err.Error()
					json.NewEncoder(c.Writer).Encode(res)
					return
				}

				res.Status = "Success"
				res.Message = "Email has successfully been confirmed"
				json.NewEncoder(c.Writer).Encode(res)
				return
			} else {
				res.Status = "Error"
				res.Message = "Session has expired. Try again"
				json.NewEncoder(c.Writer).Encode(res)
				return
			}
		} else {
			res.Status = "Error"
			res.Message = "Wrong credentials. Try again"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}
	} else {
		res.Status = "Error"
		res.Message = "Wrong credentials. Try again"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
}

func PhoneConfirmation(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")

	var res responses.ResponseMessage
	var err error

	phone := c.Request.URL.Query().Get("phone")
	token := c.Request.URL.Query().Get("confirm_token")

	var collection = DB.Collection("users")

	var result models.User
	err = collection.FindOne(context.Background(), bson.D{{"phone", phone}}).Decode(&result)
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if result.ConfirmToken != "" && token != "" {
		if result.ConfirmToken == token {
			expiryTime := result.ConfirmTokenExpiry.Time()

			if time.Now().Before(expiryTime) {
				update := bson.M{"$set": bson.M{"phone_confirmed": true, "confirm_token": "", "confirm_token_expiry": primitive.NewDateTimeFromTime(time.Now())}}
				_, err = collection.UpdateOne(context.Background(), bson.D{{"phone", phone}}, update)
				if err != nil {
					res.Status = "Error"
					res.Message = err.Error()
					json.NewEncoder(c.Writer).Encode(res)
					return
				}

				res.Status = "Success"
				res.Message = "Phone has successfully been confirmed"
				json.NewEncoder(c.Writer).Encode(res)
				return
			} else {
				res.Status = "Error"
				res.Message = "Session has expired. Try again"
				json.NewEncoder(c.Writer).Encode(res)
				return
			}
		} else {
			res.Status = "Error"
			res.Message = "Wrong credentials. Try again"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}
	} else {
		res.Status = "Error"
		res.Message = "Empty credentials. Try again"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
}

func CheckNotifRead(c *gin.Context) {
	c.Writer.Header().Set("Context-Type", "application/x-www-form-urlencoded")
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Content-Type", "application/json")

	var checkNotif responses.CheckNotifData
	var res responses.GenericResponse
	collection := DB.Collection("users")

	tokenString := c.Request.Header.Get("Authorization")
	userData, isLoggedIn := LoggedInUser(tokenString)
	if isLoggedIn {
		err := collection.FindOne(context.Background(), bson.M{"_id": userData.ID}).Decode(&checkNotif)
		if err != nil {
			res.Status = "Error"
			res.Message = "Error retrieving notification info"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		res.Status = "Success"
		res.Message = "Notification check info retrieved"
		res.Data = checkNotif
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
}

func GenerateConfirmToken(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	var user models.User
	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &user)
	var res responses.ResponseMessage
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	var filter bson.D
	var message string
	if user.Email != "" {
		filter = append(filter, bson.E{"email", user.Email})
		message = "Confirmation has been sent to your email"
	}
	if user.Phone != "" {
		filter = append(filter, bson.E{"phone", user.Phone})
		message = "Confirmation has been sent to your phone"
	}

	var result models.User
	var collection = DB.Collection("users")
	err = collection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"_id":                  user.ID,
		"email":                user.Email,
		"first_name":           user.FirstName,
		"last_name":            user.LastName,
		"avatar":               user.AvatarURL,
		"confirm_token_expiry": primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 1)),
	})
	tokenString, err := token.SignedString([]byte(os.Getenv("MY_JWT_TOKEN")))

	update := bson.M{"$set": bson.M{"confirm_token": tokenString, "confirm_token_expiry": primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 1))}}
	_, err = collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		res.Status = "Error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if user.Email != "" {
		SendEmailConfirmation(tokenString, user.Email, user.ConfirmSource)
	}
	if user.Phone != "" {
		SendPhoneConfirmation(tokenString, user.Phone, user.ConfirmSource)
	}

	res.Status = "Success"
	res.Message = message
	json.NewEncoder(c.Writer).Encode(res)
	return
}

func GeneratePhoneCode(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")

	var res responses.GenericResponse
	tokenString := c.Request.Header.Get("Authorization")
	userData, isLoggedIn := LoggedInUser(tokenString)
	if isLoggedIn {
		var user models.User
		body, _ := ioutil.ReadAll(c.Request.Body)
		err := json.Unmarshal(body, &user)
		var res responses.ResponseMessage
		if err != nil {
			res.Status = "Error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
		b := make([]byte, 6)
		n, err := io.ReadAtLeast(rand.Reader, b, 6)
		if n != 6 {
			panic(err)
		}
		for i := 0; i < len(b); i++ {
			b[i] = table[int(b[i])%len(table)]
		}

		update := bson.M{"$set": bson.M{"phone_confirm_code": string(b), "phone_confirm_expiry": primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15))}}
		_, err = DB.Collection("users").UpdateOne(context.Background(), bson.M{"_id": userData.ID}, update)
		if err != nil {
			res.Status = "Error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		SendPhoneConfirmationCode(string(b), user.Phone)
		res.Status = "Success"
		res.Message = "Phone Confirmation Code Generated"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	res.Status = "Error"
	res.Message = "Unauthorized"
	json.NewEncoder(c.Writer).Encode(res)
	return
}

func ConfirmPhone(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")

	var res responses.GenericResponse
	tokenString := c.Request.Header.Get("Authorization")
	userData, isLoggedIn := LoggedInUser(tokenString)
	if isLoggedIn {
		var phoneConfirm responses.PhoneConfirmation
		body, _ := ioutil.ReadAll(c.Request.Body)
		err := json.Unmarshal(body, &phoneConfirm)
		var res responses.ResponseMessage
		if err != nil {
			res.Status = "Error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var collection = DB.Collection("users")
		var user models.User
		err = collection.FindOne(context.Background(), bson.M{"_id": userData.ID}).Decode(&user)
		if err != nil {
			res.Status = "Error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		if time.Now().After(user.PhoneConfirmExpiry.Time()) {
			res.Status = "Error"
			res.Message = "Session has expired. Try again"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		if user.PhoneConfirmCode == phoneConfirm.PhoneConfirmCode {
			update := bson.M{"$set": bson.M{"phone_confirmed": true, "phone_confirm_code": "", "phone_confirm_expiry": primitive.NewDateTimeFromTime(time.Now())}}
			_, err = collection.UpdateOne(context.Background(), bson.M{"_id": userData.ID}, update)
			if err != nil {
				res.Status = "Error"
				res.Message = err.Error()
				json.NewEncoder(c.Writer).Encode(res)
				return
			}

			res.Status = "Success"
			res.Message = "Phone Has Successfully been Confirmed"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		res.Status = "Error"
		res.Message = "Phone Confirmation Code Does not Match"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	res.Status = "Error"
	res.Message = "Unauthorized"
	json.NewEncoder(c.Writer).Encode(res)
	return
}

func GenerateNewToken(user models.User) (models.Token, error) {
	authTokenUUID := uuid.NewV4().String()
	refreshTokenUUID := uuid.NewV4().String()

	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"_id":            user.ID,
		"email":          user.Email,
		"phone":          user.Phone,
		"first_name":     user.FirstName,
		"last_name":      user.LastName,
		"avatar":         user.AvatarURL,
		"role":           user.Role,
		"last_active_at": primitive.NewDateTimeFromTime(time.Now()),
		"at_expiry":      primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15)),
		"at_uuid":        authTokenUUID,
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"_id":            user.ID,
		"email":          user.Email,
		"phone":          user.Phone,
		"first_name":     user.FirstName,
		"last_name":      user.LastName,
		"avatar":         user.AvatarURL,
		"role":           user.Role,
		"last_active_at": primitive.NewDateTimeFromTime(time.Now()),
		"rt_expiry":      primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 24 * 365)),
		"rt_uuid":        refreshTokenUUID,
	})

	authTokenString, err := authToken.SignedString([]byte(os.Getenv("MY_JWT_TOKEN")))
	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("MY_JWT_TOKEN")))

	var token models.Token
	if err != nil {
		return token, err
	}

	token.ID = primitive.NewObjectIDFromTimestamp(time.Now())
	token.UserID = user.ID
	token.AuthToken = authTokenString
	token.AuthTokenExpiry = primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15))
	token.AuthTokenUUID = authTokenUUID
	token.RefreshToken = refreshTokenString
	token.RefreshTokenExpiry = primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 24 * 365))
	token.RefreshTokenUUID = refreshTokenUUID

	var collection = DB.Collection("tokens")
	_, err = collection.InsertOne(context.Background(), token)

	if err != nil {
		return token, err
	}

	return token, err
}

func generateResetToken(user models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"_id":                user.ID,
		"email":              user.Email,
		"first_name":         user.FirstName,
		"reset_token_expiry": primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 1)),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("MY_JWT_TOKEN")))

	if err != nil {
		return "Error while generating token, try again", err
	}

	return tokenString, err
}
