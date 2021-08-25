package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Token struct {
	ID                 primitive.ObjectID `json:"_id" bson:"_id"`
	UserID             primitive.ObjectID `json:"user_id" bson:"user_id"`
	AuthToken          string             `json:"auth_token" bson:"auth_token"`
	AuthTokenExpiry    primitive.DateTime `json:"auth_token_expiry" bson:"auth_token_expiry"`
	AuthTokenUUID      string             `json:"auth_token_uuid" bson:"auth_token_uuid"`
	RefreshToken       string             `json:"refresh_token" bson:"refresh_token"`
	RefreshTokenExpiry primitive.DateTime `json:"refresh_token_expiry" bson:"refresh_token_expiry"`
	RefreshTokenUUID   string             `json:"refresh_token_uuid" bson:"refresh_token_uuid"`
}
