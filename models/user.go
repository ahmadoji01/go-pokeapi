package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Email     string             `json:"email" bson:"email"`
	FirstName string             `json:"first_name" bson:"first_name"`
	LastName  string             `json:"last_name" bson:"last_name"`

	Password     string `json:"password,omitempty" bson:"password,omitempty"`
	Token        string `json:"authentication_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`

	CreatedAt primitive.DateTime `json:"created_at,omitempty" bson:"created_at,omitempty"`
	UpdatedAt primitive.DateTime `json:"updated_at,omitempty" bson:"updated_at,omitempty"`

	AuthTokenExpiry    primitive.DateTime `json:"auth_token_expiry,omitempty"`
	RefreshTokenExpiry primitive.DateTime `json:"refresh_token_expiry,omitempty"`
}

type MyPokemon struct {
	ID           primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	PokemonID    primitive.ObjectID `json:"pokemon_id" bson:"pokemon_id"`
	UserID       primitive.ObjectID `json:"user_id" bson:"user_id"`
	Name         string             `json:"name" bson:"name"`
	BaseName     string             `json:"base_name" bson:"base_name"`
	TimesRenamed int                `json:"times_renamed" bson:"times_renamed"`

	CreatedAt primitive.DateTime `json:"created_at,omitempty" bson:"created_at,omitempty"`
	UpdatedAt primitive.DateTime `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
}

type ResponseResult struct {
	Error  string `json:"error"`
	Result string `json:"result"`
}
