package middleware

import (
	"context"
	"fmt"
	"log"

	"pokeapi_module/config"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DB connection string
// for localhost mongoDB
const connectionString = "mongodb://localhost:27017"

// Database Name
const dbName = "gopokeapi"

// Database instance
var DB *mongo.Database

var IsProduction = false

// create connection with mongo DB
func init() {

	// Set client options
	clientOptions := options.Client().ApplyURI(connectionString)

	// connect to MongoDB
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

func HandlePreflight(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", config.CORS)
	c.Writer.Header().Set("Access-Control-Allow-Methods", "PATCH, POST, OPTIONS, GET")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
	return
}
