package main

import (
	"auth/db"
	"auth/tokens"
	"auth/types"
	"encoding/json"
	"fmt"
	"strings"

	"log"
	"net/http"
	"os"
	"time"

	"github.com/jameskeane/bcrypt"
	"go.mongodb.org/mongo-driver/mongo"

	b64url "github.com/dvsekhvalnov/jose2go/base64url"
	"github.com/joho/godotenv"
)

var jwtExpTime = time.Minute * 10
var refreshExpTime = time.Hour * 720
var secret = os.Getenv("SECRET")
var bcryptCost = 10

func main() {
	log.Println("started")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	mongoURI := os.Getenv("MONGO_URI")
	err = db.Connect(mongoURI)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", auth)
	mux.HandleFunc("/refresh", refresh)
	err = http.ListenAndServe(":3000", mux)
	if err != nil {
		log.Fatal(err)
	}

}

func auth(w http.ResponseWriter, r *http.Request) {
	param, contains := r.Header["Guid"]
	if !contains {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("error: looks like guid was not passed"))
		return
	}
	guid := param[0]

	accToken, err := tokens.GenJWT(guid, secret, jwtExpTime)
	if err != nil {
		log.Fatal(err)
	}
	refToken, err := tokens.GenRefresh()
	if err != nil {
		log.Fatal(err)
	}
	salt, err := bcrypt.Salt(bcryptCost)
	if err != nil {
		log.Fatal(err)
	}
	hashed, err := bcrypt.Hash(refToken, salt)
	if err != nil {
		log.Fatal(err)
	}

	doc := types.RefreshTokenObj{
		HashedToken: hashed,
		Sub:         guid,
		Exp:         time.Now().Add(refreshExpTime).Unix(),
	}

	db.Add(doc)
	if err != nil {
		log.Fatal(err)
	}
	b64encoded := b64url.Encode([]byte(fmt.Sprintf("%s:%s", salt, refToken)))

	responseObj := types.Response{
		Access:  accToken,
		Refresh: b64encoded,
	}
	b, err := json.Marshal(responseObj)
	if err != nil {
		log.Fatal(err)
	}
	w.Write(b)

}

func refresh(w http.ResponseWriter, r *http.Request) {
	re, err := b64url.Decode(r.Header["Refresh"][0])
	if err != nil {
		log.Fatal(err)
	}
	t := strings.Split(string(re), ":") // the salt is before the colon, and the non-hashed token is after the colon
	if len(t) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("error: invalid format of refresh token; re-auth required"))
		return
	}
	hashed, err := bcrypt.Hash(t[1], t[0])
	if err != nil {
		log.Fatal(err)
	}
	token, err := db.Get(hashed)

	if err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("error: refresh token expired or invalid; re-auth required"))
			return
		default:
			log.Fatal(err)
		}
	}

	if time.Now().Unix() >= token.Exp {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("error: refresh token expired; re-auth required"))
		return
	} else {
		accToken, err := tokens.GenJWT(token.Sub, secret, jwtExpTime)
		if err != nil {
			log.Fatal(err)
		}
		refToken, err := tokens.GenRefresh()
		if err != nil {
			log.Fatal(err)
		}
		salt, err := bcrypt.Salt(bcryptCost)
		if err != nil {
			log.Fatal(err)
		}
		b64encoded := b64url.Encode([]byte(fmt.Sprintf("%s:%s", salt, refToken)))
		responseObj := types.Response{
			Access:  accToken,
			Refresh: b64encoded,
		}
		response, err := json.Marshal(responseObj)
		if err != nil {
			log.Fatal(err)
		}
		hashed, err := bcrypt.Hash(refToken)
		if err != nil {
			log.Fatal(err)
		}

		newToken := types.RefreshTokenObj{
			HashedToken: hashed,
			Sub:         token.Sub,
			Exp:         time.Now().Add(refreshExpTime).Unix(),
		}
		err = db.Add(newToken)
		if err != nil {
			log.Fatal(err)
		}
		err = db.Remove(token)
		if err != nil {
			log.Fatal(err)
		}
		w.Write(response)

	}
}
