package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Pokemon struct {
	ID          primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	ImgURL      string             `json:"img_url" bson:"img_url"`

	CreatedAt primitive.DateTime `json:"created_at" bson:"created_at"`
	UpdatedAt primitive.DateTime `json:"updated_at" bson:"updated_at"`

	Moves []Move `json:"moves" bson:"moves"`
	Types []Type `json:"types" bson:"types"`
}

type Type struct {
	Name string `json:"name" bson:"name"`
}

type Move struct {
	Name string `json:"name" bson:"name"`
}
