package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"cloud.google.com/go/storage"

	sal "github.com/salrashid123/oauth2/vault"
	"google.golang.org/api/option"
)

var (
	projectId  = "pubsub-msg"
	bucketName = "pubsub-msg-bucket"
	objectName = "somefile.txt"
)

func main() {
	ts, err := sal.VaultTokenSource(
		&sal.VaultTokenConfig{
			VaultToken: "s.URldGrQaEajbEgZB9KLjOJPQ",
			VaultPath:  "gcp/token/my-token-roleset",
			// VaultCAcert: "CA_crt.pem",
			VaultAddr: "http://localhost:8200",
		},
	)

	// tok, err := kmsTokenSource.Token()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// //log.Printf("Token: %v", tok.AccessToken)

	tok, err := ts.Token()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Token: %v", tok.AccessToken)

	ctx := context.Background()

	storageClient, err := storage.NewClient(ctx, option.WithTokenSource(ts))
	if err != nil {
		log.Fatal(err)
	}
	bkt := storageClient.Bucket(bucketName)
	obj := bkt.Object(objectName)
	r, err := obj.NewReader(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading object %s\n", err)
		return
	}
	fmt.Println()
	defer r.Close()
	if _, err := io.Copy(os.Stdout, r); err != nil {
		fmt.Fprintf(os.Stderr, "Error closing writer %s\n", err)
		return
	}
	fmt.Println()
}
