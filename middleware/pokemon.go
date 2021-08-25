package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"pokeapi_module/config"
	"pokeapi_module/models"
	"pokeapi_module/responses"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func GetAllPokemons(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "GET")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")

	var collection = DB.Collection("pokemons")
	var pokemons []models.Pokemon
	var resp responses.PokemonsResp
	var msg responses.ResponseMessage

	cur, err := collection.Find(context.Background(), bson.D{})
	if err != nil {
		msg.Status = "error"
		msg.Message = "Error while getting pokemons from DB, try again"
		json.NewEncoder(c.Writer).Encode(msg)
		return
	}

	for cur.Next(context.Background()) {
		var result models.Pokemon
		e := cur.Decode(&result)
		if e != nil {
			msg.Status = "error"
			msg.Message = "Error while decoding pokemons' data, try again"
			json.NewEncoder(c.Writer).Encode(msg)
			return
		}
		pokemons = append(pokemons, result)
	}
	if err := cur.Err(); err != nil {
		msg.Status = "error"
		msg.Message = "Error while retrieving pokemons' data, try again"
		json.NewEncoder(c.Writer).Encode(msg)
		return
	}
	cur.Close(context.Background())

	resp.Status = "success"
	resp.Message = "Pokemons Loaded"
	resp.Data = pokemons

	json.NewEncoder(c.Writer).Encode(resp)
}

func GetPokemonDetail(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "GET")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")

	var collection = DB.Collection("pokemons")
	pokemonID, err := primitive.ObjectIDFromHex(c.Param("id"))

	var msg responses.ResponseMessage
	if err != nil {
		msg.Status = "error"
		msg.Message = "Error while converting ID, try again"
		json.NewEncoder(c.Writer).Encode(msg)
		return
	}

	var resp responses.PokemonResp
	var pokemon models.Pokemon
	err = collection.FindOne(context.Background(), bson.M{"_id": pokemonID}).Decode(&pokemon)
	if err != nil {
		msg.Status = "error"
		msg.Message = "Error while retrieving pokemon's data, try again"
		json.NewEncoder(c.Writer).Encode(msg)
		return
	}

	resp.Status = "success"
	resp.Message = "Pokemon Details Loaded"
	resp.Data = pokemon
	json.NewEncoder(c.Writer).Encode(resp)
}

func CatchPokemon(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	var res responses.ResponseMessage

	tokenString := c.Request.Header.Get("Authorization")
	userData, isLoggedIn := LoggedInUser(tokenString)

	if !isLoggedIn {
		res.Status = "error"
		res.Message = "Unauthorized"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	chance := rand.Intn(100)
	if chance > 51 {
		res.Status = "pokemon_escaped"
		res.Message = "Too bad, you failed to catch the pokemon"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	var myPokemon models.MyPokemon
	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &myPokemon)
	if err != nil {
		res.Status = "error"
		res.Message = "Error encoding request body"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if myPokemon.ID.IsZero() {
		res.Status = "error"
		res.Message = "No pokemon to be caught"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	myPokemon.ID = primitive.NewObjectIDFromTimestamp(time.Now())
	myPokemon.UserID = userData.ID
	myPokemon.TimesRenamed = 0
	myPokemon.CreatedAt = primitive.NewDateTimeFromTime(time.Now())
	myPokemon.UpdatedAt = primitive.NewDateTimeFromTime(time.Now())

	var collection = DB.Collection("my_pokemons")
	_, err = collection.InsertOne(context.Background(), myPokemon)
	if err != nil {
		res.Status = "error"
		res.Message = "Something went wrong"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	res.Status = "success"
	res.Message = "You are one step closer to become a pokemon master!"
	json.NewEncoder(c.Writer).Encode(res)
}

func ReleasePokemon(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	var res responses.ResponseMessage

	tokenString := c.Request.Header.Get("Authorization")
	userData, isLoggedIn := LoggedInUser(tokenString)

	if !isLoggedIn {
		res.Status = "error"
		res.Message = "Unauthorized"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	min := 1
	max := 20
	number := rand.Intn(max-min) + min
	fmt.Println(number)
	if !isPrimeNumber(number, min, max) {
		res.Status = "pokemon_wont_release"
		res.Message = "Too bad, your pokemon is not willing to release itself"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	var myPokemon models.MyPokemon
	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &myPokemon)
	if err != nil {
		res.Status = "error"
		res.Message = "Error encoding request body"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if myPokemon.ID.IsZero() {
		res.Status = "error"
		res.Message = "No pokemon to be released"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	var collection = DB.Collection("my_pokemons")
	err = collection.FindOne(context.Background(), bson.M{"_id": myPokemon.ID}).Decode(&myPokemon)
	if err != nil {
		res.Status = "error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if myPokemon.UserID != userData.ID {
		res.Status = "error"
		res.Message = "You are not authorized to release this pokemon"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	_, err = collection.DeleteOne(context.Background(), bson.M{"_id": myPokemon.ID})
	if err != nil {
		res.Status = "error"
		res.Message = "Something went wrong"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	res.Status = "success"
	res.Message = "Your pokemon has sadly been released"
	json.NewEncoder(c.Writer).Encode(res)
}

func RenameMyPokemon(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "PATCH")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	c.Writer.Header().Set("Content-Type", "application/json")
	var res responses.GenericResponse

	tokenString := c.Request.Header.Get("Authorization")
	userData, isLoggedIn := LoggedInUser(tokenString)

	if !isLoggedIn {
		res.Status = "error"
		res.Message = "Unauthorized"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	var reqData models.MyPokemon
	var myPokemon models.MyPokemon
	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &reqData)
	if err != nil {
		res.Status = "error"
		res.Message = "Error encoding request body"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if reqData.ID.IsZero() {
		res.Status = "error"
		res.Message = "No pokemon to be renamed"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	var collection = DB.Collection("my_pokemons")
	err = collection.FindOne(context.Background(), bson.M{"_id": reqData.ID}).Decode(&myPokemon)
	if err != nil {
		res.Status = "error"
		res.Message = err.Error()
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	if myPokemon.UserID != userData.ID {
		res.Status = "error"
		res.Message = "You are not authorized to edit this pokemon"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	newName := reqData.Name
	baseName := myPokemon.BaseName
	timesRenamed := 0
	if reqData.Name == "" {
		affix := generateFibonacci(myPokemon.TimesRenamed)
		timesRenamed = myPokemon.TimesRenamed + 1
		newName = myPokemon.BaseName + "-" + strconv.Itoa(affix)
	} else {
		baseName = reqData.Name
	}

	update := bson.M{"$set": bson.M{"base_name": baseName, "name": newName, "times_renamed": timesRenamed}}
	updatedData, err := collection.UpdateOne(context.Background(), bson.M{"_id": myPokemon.ID}, update)
	if err != nil {
		res.Status = "error"
		res.Message = "Error updating your pokemon's data. Try again"
		json.NewEncoder(c.Writer).Encode(res)
		return
	}

	res.Status = "success"
	res.Message = "Your pokemon has been successfully edited"
	res.Data = updatedData
	json.NewEncoder(c.Writer).Encode(res)
}

func isPrimeNumber(n int, min int, max int) bool {
	i := 0
	j := 0

	prime := make([]bool, max+1)
	for i = 2; i <= max; i++ {
		prime[i] = true
	}

	for i = 2; i*i <= max; i++ {
		if prime[i] {
			for j = i * i; j <= n; j += i {
				prime[j] = false
			}
		}
	}

	return prime[n]
}

func generateFibonacci(n int) int {
	if n <= 1 {
		return n
	}
	return generateFibonacci(n-1) + generateFibonacci(n-2)
}
