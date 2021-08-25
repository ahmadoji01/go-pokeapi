package router

import (
	"github.com/gin-gonic/gin"
	"gitlab.com/kitalabs/go-2gaijin/middleware"
)

// Router is exported and used in main.go
func Router() *gin.Engine {

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.GET("/", middleware.GetHome)
	r.GET("/pokemon/:id", middleware.GetPokemonDetail)
	r.GET("/pokemons", middleware.GetAllPokemons)
	r.GET("/search", middleware.GetSearch)
	r.POST("/catch_pokemon", middleware.CatchPokemon)
	r.PATCH("/rename_my_pokemon", middleware.RenameMyPokemon)
	r.GET("/my_profile", middleware.GetMyProfile)

	r.POST("/sign_in", middleware.LoginHandler)
	r.POST("/sign_up", middleware.RegisterHandler)
	r.POST("/sign_out", middleware.LogoutHandler)
	r.POST("/refresh_token", middleware.RefreshToken)
	r.POST("/update_profile", middleware.UpdateProfile)

	// Preflight Response
	r.OPTIONS("/", middleware.HandlePreflight)
	r.OPTIONS("/pokemon/:id", middleware.HandlePreflight)
	r.OPTIONS("/pokemons", middleware.HandlePreflight)
	r.OPTIONS("/search", middleware.HandlePreflight)
	r.OPTIONS("/catch_pokemon", middleware.HandlePreflight)
	r.OPTIONS("/renamy_my_pokemon", middleware.HandlePreflight)
	r.OPTIONS("/my_profile", middleware.HandlePreflight)
	r.OPTIONS("/sign_in", middleware.HandlePreflight)
	r.OPTIONS("/sign_up", middleware.HandlePreflight)
	r.OPTIONS("/sign_out", middleware.HandlePreflight)
	r.OPTIONS("/refresh_token", middleware.HandlePreflight)
	r.OPTIONS("/reset_password", middleware.HandlePreflight)

	return r
}
