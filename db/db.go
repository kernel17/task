package db

import (
	"auth/types"
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"go.mongodb.org/mongo-driver/mongo/options"
)

var mongoTokens *mongo.Collection
var ctx context.Context

func Connect(mongoURI string) error {
	ctx = context.TODO()
	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return err
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return err
	}
	mongoTokens = client.Database("auth").Collection("tokens")
	return nil
}

func Get(rtoken string) (types.RefreshTokenObj, error) {
	filter := bson.M{"hashed": rtoken}
	result := mongoTokens.FindOne(ctx, filter)
	if result.Err() != nil {
		return types.RefreshTokenObj{}, result.Err()
	}
	var obj types.RefreshTokenObj
	err := result.Decode(&obj)
	if err != nil {
		return types.RefreshTokenObj{}, err
	}
	return obj, nil
}

func Add(doc types.RefreshTokenObj) error {
	_, err := mongoTokens.InsertOne(ctx, doc)
	return err
}

func Remove(doc types.RefreshTokenObj) error {
	_, err := mongoTokens.DeleteOne(ctx, doc)
	return err
}
