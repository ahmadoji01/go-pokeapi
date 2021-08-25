package responses

import (
	"pokeapi_module/models"
)

type PokemonsResp struct {
	Status  string           `json:"status"`
	Message string           `json:"message"`
	Data    []models.Pokemon `json:"data"`
}

type PokemonResp struct {
	Status  string         `json:"status"`
	Message string         `json:"message"`
	Data    models.Pokemon `json:"data"`
}

// For Search Page
type Pagination struct {
	CurrentPage  int64 `json:"current_page"`
	NextPage     int64 `json:"next_page"`
	PreviousPage int64 `json:"previous_page"`
	TotalPages   int64 `json:"total_pages"`
	ItemsPerPage int64 `json:"items_per_page"`
	TotalItems   int64 `json:"total_items"`
}

type SearchPage struct {
	Status  string `json:"status"`
	Message string `json:"message"`

	Data interface{} `json:"data"`
}

type UserData struct {
	User models.User `json:"user"`
}

type UserWithMyPokemon struct {
	User       models.User        `json:"user"`
	MyPokemons []models.MyPokemon `json:"my_pokemons"`
}

type LoginPage struct {
	Status  string `json:"status"`
	Message string `json:"message"`

	Data UserData `json:"data"`
}

type ResponseMessage struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type SearchData struct {
	TotalItems int64       `json:"total_items"`
	Items      interface{} `json:"items"`
}

type TokenData struct {
	Token models.Token `json:"token"`
}

type GenericResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
