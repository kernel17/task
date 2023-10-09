package types

type JwtPayload struct {
	Sub string
	Iat int64
	Exp int64
}

type RefreshTokenObj struct {
	HashedToken string `bson:"hashed"`
	Sub         string `bson:"subject"`
	Exp         int64  `bson:"expires"`
}

type Response struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}
