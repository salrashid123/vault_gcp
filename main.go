package main

import (
	"flag"
	"io/ioutil"
	"log"

	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/glog"
	"golang.org/x/oauth2/google"
)

/*
 go run main.go  --serviceAccountFile=/path/to/svc-account.json --expIn 3600 --audience "http://vault/my-iam-role" --expIn=3600 --logtostderr=1 -v 5
*/

var (
	serviceAccountFile = flag.String("serviceAccountFile", "", "serviceAccountFile")
	audience           = flag.String("audience", "", "audience")
	expIn              = flag.Int("expIn", 3600, "exp in seconds")
)

func main() {
	flag.Parse()

	if *serviceAccountFile == "" || *audience == "" {
		glog.Fatalf("both serviceAccountFile and audience must be specified")
	}

	glog.Infof("Starting")

	data, err := ioutil.ReadFile(*serviceAccountFile)
	if err != nil {
		log.Fatal(err)
	}
	conf, err := google.JWTConfigFromJSON(data, "https://www.googleapis.com/auth/userinfo.email")
	if err != nil {
		log.Fatal(err)
	}

	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Unix() + int64(*expIn),
		Audience:  *audience,
		Subject:   conf.Email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = conf.PrivateKeyID

	r, err := jwt.ParseRSAPrivateKeyFromPEM(conf.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	tokenString, err := token.SignedString(r)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(tokenString)

}
