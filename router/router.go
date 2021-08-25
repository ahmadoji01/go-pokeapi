package router

import (
	"pokeapi_module/middleware"

	"github.com/gin-gonic/gin"
)

// Router is exported and used in main.go
func Router() *gin.Engine {

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.GET("/pokemon/:id", middleware.GetPokemonDetail)
	r.GET("/pokemons", middleware.GetAllPokemons)
	r.POST("/catch_pokemon", middleware.CatchPokemon)
	r.PATCH("/rename_my_pokemon", middleware.RenameMyPokemon)
	r.POST("/release_pokemon", middleware.ReleasePokemon)

	r.POST("/sign_in", middleware.LoginHandler)
	r.POST("/sign_up", middleware.RegisterHandler)
	r.DELETE("/sign_out", middleware.LogoutHandler)
	r.POST("/refresh_token", middleware.RefreshToken)
	r.PUT("/update_profile", middleware.UpdateProfile)
	r.GET("/my_profile", middleware.ProfileHandler)

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
