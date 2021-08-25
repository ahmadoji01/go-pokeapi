package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"pokeapi_module/models"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Move struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type PokeMove struct {
	Move Move `json:"move"`
}

type Sprites struct {
	BackDefault  string `json:"back_default"`
	FrontDefault string `json:"front_default"`
}

type Type struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type PokeType struct {
	Slot int  `json:"slot"`
	Type Type `json:"type"`
}

type Pokemon struct {
	Name      string     `json:"name"`
	Sprites   Sprites    `json:"sprites"`
	PokeTypes []PokeType `json:"types"`
	PokeMoves []PokeMove `json:"moves"`
}

type Poke struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Results struct {
	Pokes []Poke `json:"results"`
}

func populatePokemon(url string) {
	var data Pokemon
	var pokemon models.Pokemon
	var moves []models.Move
	var ts []models.Type

	c := http.Client{
		Timeout: time.Second * 60, // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", "")

	res, getErr := c.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	jsonErr := json.Unmarshal([]byte(body), &data)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}

	for i := 0; i < len(data.PokeMoves); i++ {
		pokeMove := data.PokeMoves[i]
		var move models.Move
		move.Name = pokeMove.Move.Name

		moves = append(moves, move)
	}

	for i := 0; i < len(data.PokeTypes); i++ {
		pokeType := data.PokeTypes[i]
		var t models.Type
		t.Name = pokeType.Type.Name

		ts = append(ts, t)
	}

	pokemon.Name = data.Name
	pokemon.Moves = moves
	pokemon.Types = ts
	pokemon.ImgURL = data.Sprites.FrontDefault

	err = insertPokemon(pokemon)
	if err != nil {
		log.Fatal(err)
	}

}

const connectionString = "mongodb://localhost:27017"
const dbName = "gopokeapi"

var DB *mongo.Database

func initDB() {
	clientOptions := options.Client().ApplyURI(connectionString)

	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")
	DB = client.Database(dbName)
}

func insertPokemon(pokemon models.Pokemon) error {
	pokemon.ID = primitive.NewObjectIDFromTimestamp(time.Now())
	pokemon.CreatedAt = primitive.NewDateTimeFromTime(time.Now())
	pokemon.UpdatedAt = primitive.NewDateTimeFromTime(time.Now())

	var collection = DB.Collection("pokemons")
	_, err := collection.InsertOne(context.TODO(), pokemon)

	return err
}

func main() {
	initDB()

	limit := "10"
	offset := "0"
	if len(os.Args) >= 3 {
		limit = string(os.Args[1])
		offset = string(os.Args[2])
	}

	url := "https://pokeapi.co/api/v2/pokemon?limit=" + limit + "&offset=" + offset
	fmt.Println(url)
	var pokes Results

	c := http.Client{
		Timeout: time.Second * 120, // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", "")

	res, getErr := c.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	jsonErr := json.Unmarshal([]byte(body), &pokes)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}

	for i := 0; i < len(pokes.Pokes); i++ {
		p := pokes.Pokes[i]
		populatePokemon(p.URL)
	}
}
