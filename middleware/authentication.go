package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"pokeapi_module/config"
	"pokeapi_module/models"
	"pokeapi_module/responses"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/twinj/uuid"
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
		res.Status = "error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if user.Email == "" || user.Password == "" {
		res.Status = "error"
		res.Message = "Invalid credentials"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if user.FirstName == "" {
		res.Status = "error"
		res.Message = "First name must not be empty"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	collection := DB.Collection("users")

	if err != nil {
		res.Status = "error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
	var result models.User
	err = collection.FindOne(context.TODO(), bson.D{{"email", user.Email}}).Decode(&result)

	if err == nil {
		res.Status = "error"
		res.Message = "Email already exists"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if err.Error() == "mongo: no documents in result" {
		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)

		if err != nil {
			res.Status = "error"
			res.Message = "Error while hashing password. Try again"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}
		user.ID = primitive.NewObjectIDFromTimestamp(time.Now())
		user.Password = string(hash)
		user.CreatedAt = primitive.NewDateTimeFromTime(time.Now())
		user.UpdatedAt = primitive.NewDateTimeFromTime(time.Now())

		_, err = collection.InsertOne(context.TODO(), user)
		if err != nil {
			res.Status = "error"
			res.Message = "Error while creating user. Try again"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		tokenString, err := GenerateNewToken(user)
		if err != nil {
			res.Status = "error"
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

		res.Status = "success"
		res.Message = "Registration successful"
		res.Data = userData

		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	res.Status = "error"
	res.Message = err.Error()
	json.NewEncoder(c.Writer).Encode(res)
}

func LoginHandler(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	var user models.User
	var res responses.ResponseMessage
	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &user)

	collection := DB.Collection("users")
	if err != nil {
		res.Status = "error"
		res.Message = "Error processing request body"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	var result models.User
	var options = &options.FindOptions{}
	options.SetProjection(bson.M{
		"_id":        1,
		"first_name": 1,
		"last_name":  1,
		"token":      1,
	})

	if user.Email == "" || user.Password == "" {
		res.Status = "error"
		res.Message = "Invalid credentials"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	err = collection.FindOne(context.TODO(), bson.D{{"email", user.Email}}).Decode(&result)
	if err != nil {
		res.Status = "error"
		res.Message = "Invalid email"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))

	if err != nil {
		res.Status = "error"
		res.Message = "Invalid password"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	tokenString, err := GenerateNewToken(result)
	if err != nil {
		res.Status = "error"
		res.Message = "Error while generating token, try again"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	result.Token = tokenString.AuthToken
	result.RefreshToken = tokenString.RefreshToken
	result.AuthTokenExpiry = tokenString.AuthTokenExpiry
	result.RefreshTokenExpiry = tokenString.RefreshTokenExpiry
	result.Password = ""

	var userData responses.UserData
	userData.User = result

	var resp responses.GenericResponse

	resp.Status = "success"
	resp.Message = "Login Successful"
	resp.Data = userData
	json.NewEncoder(c.Writer).Encode(resp)
}

func ProfileHandler(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "GET")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	tokenString := c.Request.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(os.Getenv("MY_JWT_TOKEN")), nil
	})

	var result models.User
	var msg responses.ResponseMessage
	var profileData responses.UserWithMyPokemon

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		msg.Status = "error"
		msg.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(msg)
		return
	}

	id, _ := primitive.ObjectIDFromHex(claims["_id"].(string))

	err = DB.Collection("users").FindOne(context.Background(), bson.M{"_id": id}).Decode(&result)
	if err != nil {
		msg.Status = "error"
		msg.Message = "Something went wrong. Please try again"
		json.NewEncoder(c.Writer).Encode(msg)
		return
	}

	AtUUID := claims["at_uuid"].(string)
	var collection = DB.Collection("tokens")
	var tokenDetail models.Token
	err = collection.FindOne(context.Background(), bson.M{"auth_token_uuid": AtUUID}).Decode(&tokenDetail)
	if err != nil {
		msg.Status = "error"
		msg.Message = "Unauthorized"
		json.NewEncoder(c.Writer).Encode(msg)
		return
	}

	AtExpiry, _ := time.Parse(time.RFC3339, claims["at_expiry"].(string))
	if time.Now().After(AtExpiry) {
		msg.Status = "error"
		msg.Message = "Token expired"
		json.NewEncoder(c.Writer).Encode(msg)
		return
	}

	result.ID = id
	result.Password = ""
	profileData.User = result

	collection = DB.Collection("my_pokemons")
	cur, err := collection.Find(context.Background(), bson.M{"user_id": result.ID})
	if err != nil {
		msg.Status = "error"
		msg.Message = "Error while getting pokemons from DB, try again"
		json.NewEncoder(c.Writer).Encode(msg)
		return
	}

	myPokemons := []models.MyPokemon{}
	for cur.Next(context.Background()) {
		var result models.MyPokemon
		e := cur.Decode(&result)
		if e != nil {
			msg.Status = "error"
			msg.Message = "Error while decoding pokemons' data, try again"
			json.NewEncoder(c.Writer).Encode(msg)
			return
		}
		myPokemons = append(myPokemons, result)
	}
	if err := cur.Err(); err != nil {
		msg.Status = "error"
		msg.Message = "Error while retrieving pokemons' data, try again"
		json.NewEncoder(c.Writer).Encode(msg)
		return
	}
	cur.Close(context.Background())

	var resp responses.GenericResponse
	if err != nil {
		msg.Status = "error"
		msg.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(resp)
		return
	}

	profileData.MyPokemons = myPokemons
	resp.Status = "success"
	resp.Message = "Profile Successfully Retrieved"
	resp.Data = profileData

	json.NewEncoder(c.Writer).Encode(resp)
}

func UpdateProfile(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "PUT")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	tokenString := c.Request.Header.Get("Authorization")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(os.Getenv("MY_JWT_TOKEN")), nil
	})
	var res responses.ResponseMessage

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		id, err := primitive.ObjectIDFromHex(claims["_id"].(string))

		if err != nil {
			res.Status = "error"
			res.Message = "Something went wrong. Please try again"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		AtUUID := claims["at_uuid"].(string)
		var collection = DB.Collection("tokens")
		var tokenDetail models.Token
		err = collection.FindOne(context.Background(), bson.M{"auth_token_uuid": AtUUID}).Decode(&tokenDetail)
		if err != nil {
			res.Status = "error"
			res.Message = "Unauthorized"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		AtExpiry, _ := time.Parse(time.RFC3339, claims["at_expiry"].(string))
		if time.Now().After(AtExpiry) {
			res.Status = "error"
			res.Message = "Token expired"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var user models.User
		body, _ := ioutil.ReadAll(c.Request.Body)
		err = json.Unmarshal(body, &user)
		var res responses.ResponseMessage
		if err != nil {
			res.Status = "error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		if user.Email == "" || user.FirstName == "" {
			res.Status = "error"
			res.Message = "Email/first name should not be empty"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var filter = bson.M{"_id": id}
		var update = bson.M{"$set": bson.M{"first_name": user.FirstName, "last_name": user.LastName, "email": user.Email}}

		collection = DB.Collection("users")
		_, err = collection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			res.Status = "error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var newProfile models.User
		err = collection.FindOne(context.Background(), filter).Decode(&newProfile)
		if err != nil {
			res.Status = "error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"_id":        id,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"at_expiry":  primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15)),
			"at_uuid":    AtUUID,
		})
		authTokenString, err := authToken.SignedString([]byte(os.Getenv("MY_JWT_TOKEN")))
		if err != nil {
			res.Status = "error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		update = bson.M{"$set": bson.M{"auth_token": authTokenString, "auth_token_expiry": primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15))}}
		_, err = collection.UpdateOne(context.Background(), bson.D{{"auth_token_uuid", AtUUID}}, update)
		if err != nil {
			res.Status = "error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}
		user.Token = authTokenString

		var resp responses.GenericResponse
		resp.Status = "success"
		resp.Message = "Profile Successfully Updated"
		resp.Data = user

		json.NewEncoder(c.Writer).Encode(resp)
		return
	}

	res.Status = "error"
	res.Message = err.Error()
	json.NewEncoder(c.Writer).Encode(res)
}

func LogoutHandler(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "DELETE")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	tokenString := c.Request.Header.Get("Authorization")
	var res responses.ResponseMessage
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(os.Getenv("MY_JWT_TOKEN")), nil
	})
	if err != nil {
		res.Status = "error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if err != nil {
			res.Status = "error"
			res.Message = err.Error()
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		AtExpiry, _ := time.Parse(time.RFC3339, claims["at_expiry"].(string))
		if time.Now().After(AtExpiry) {
			res.Status = "error"
			res.Message = "Unauthorized"
			json.NewEncoder(c.Writer).Encode(res)
			return
		}

		var AtUUID = claims["at_uuid"].(string)
		var collection = DB.Collection("tokens")
		collection.FindOneAndDelete(context.Background(), bson.M{"auth_token_uuid": AtUUID})
	} else {
		res.Status = "error"
		res.Message = "Unauthorized"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
	res.Status = "success"
	res.Message = "You have been logged out successfully"
	json.NewEncoder(c.Writer).Encode(res)
}

func LoggedInUser(tokenString string) (models.User, bool) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(os.Getenv("MY_JWT_TOKEN")), nil
	})

	var result models.User

	if err != nil {
		return result, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return result, false
	}

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

	return result, true
}

func RefreshToken(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	tokenString := c.Request.Header.Get("Authorization")
	var res responses.ResponseMessage
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(os.Getenv("MY_JWT_TOKEN")), nil
	})

	var tokenDetail models.Token

	if err != nil {
		res.Status = "error"
		res.Message = "Something went wrong. Please try again"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		res.Status = "error"
		res.Message = "Token Expired"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	id, err := primitive.ObjectIDFromHex(claims["_id"].(string))
	if err != nil {
		res.Status = "error"
		res.Message = "Something went wrong. Please try again"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	RtExpiry, _ := time.Parse(time.RFC3339, claims["rt_expiry"].(string))
	if time.Now().After(RtExpiry) {
		res.Status = "error"
		res.Message = "Token Expired"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	RtUUID := claims["rt_uuid"].(string)
	var collection = DB.Collection("tokens")
	err = collection.FindOne(context.Background(), bson.M{"refresh_token_uuid": RtUUID}).Decode(&tokenDetail)
	if err != nil {
		res.Status = "error"
		res.Message = "Unauthorized"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"_id":        id,
		"email":      claims["email"].(string),
		"first_name": claims["first_name"].(string),
		"last_name":  claims["last_name"].(string),
		"at_expiry":  primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15)),
		"at_uuid":    tokenDetail.AuthTokenUUID,
	})
	authTokenString, _ := authToken.SignedString([]byte(os.Getenv("MY_JWT_TOKEN")))

	update := bson.M{"$set": bson.M{"auth_token": authTokenString, "auth_token_expiry": primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15))}}
	_, err = collection.UpdateOne(context.Background(), bson.D{{"refresh_token_uuid", RtUUID}}, update)
	if err != nil {
		res.Status = "error"
		res.Message = "Something went wrong"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}
	tokenDetail.AuthToken = authTokenString
	tokenDetail.AuthTokenExpiry = primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15))

	var resp responses.GenericResponse
	var tokenData responses.TokenData
	tokenData.Token = tokenDetail

	resp.Status = "success"
	resp.Message = "Token Refreshed"
	resp.Data = tokenData
	json.NewEncoder(c.Writer).Encode(resp)
}

func GenerateNewToken(user models.User) (models.Token, error) {
	authTokenUUID := uuid.NewV4().String()
	refreshTokenUUID := uuid.NewV4().String()

	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"_id":        user.ID,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"at_expiry":  primitive.NewDateTimeFromTime(time.Now().Add(time.Minute * 15)),
		"at_uuid":    authTokenUUID,
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"_id":        user.ID,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"rt_expiry":  primitive.NewDateTimeFromTime(time.Now().Add(time.Hour * 24 * 365)),
		"rt_uuid":    refreshTokenUUID,
	})

	var token models.Token
	authTokenString, _ := authToken.SignedString([]byte(os.Getenv("MY_JWT_TOKEN")))
	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("MY_JWT_TOKEN")))

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
