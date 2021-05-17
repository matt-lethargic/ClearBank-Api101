package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type AuthProfile struct {
	Token          string
	PrivateKeyPath string
	PublicKeyPath  string
}

var authProfile AuthProfile

func main() {

	authProfile = AuthProfile{
		Token:          "<token-here>",
		PrivateKeyPath: "GoClearBank.key",
		PublicKeyPath:  "GoClearBank.pub"}

	r := mux.NewRouter()
	r.HandleFunc("/api", handleApi)
	r.HandleFunc("/webhook", handleWebhook)

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func handleApi(w http.ResponseWriter, r *http.Request) {
	apiRequest := ApiRequest{
		Echo: "Let's Go ClearBank, let's go!",
	}

	// digital signature
	apiRequestText, err := json.Marshal(apiRequest)
	if err != nil {
		fmt.Println(err)
	}

	// load private key
	privateKey, err := loadPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	dgitalSignature, err := Generate(apiRequestText, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(dgitalSignature)

	// request
	requestBody := bytes.NewBuffer(apiRequestText)
	fmt.Println("Request: " + string(apiRequestText))
	req, err := http.NewRequest("POST", "https://testlemur-institution-api-uksouth.azurewebsites.net/v1/test", requestBody)
	if err != nil {
		log.Fatal(err)
	}

	// headers
	id := uuid.New()
	req.Header.Add("X-Request-Id", id.String())
	req.Header.Add("DigitalSignature", dgitalSignature)
	req.Header.Add("Authorization", "Bearer "+authProfile.Token)
	req.Header.Add("Content-Type", "application/json")

	// send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// check response
	correlationId := resp.Header.Get("X-Correlation-Id")
	fmt.Println("Status Code: " + resp.Status)
	fmt.Println("Correlation ID: " + correlationId)

	defer resp.Body.Close()

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Body: "))
	w.Write(bytes)
	w.Write([]byte("\nCorrelation Id: "))
	w.Write([]byte(correlationId))
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {

	// load public key
	publicKey, err := loadPublicKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(err)
		return
	}

	// get web request
	defer r.Body.Close()

	requestBodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println(err)
		return
	}

	// verify digital signature
	digitalSignature := []byte(r.Header.Get("DigitalSignature"))

	verified, err := Verify(requestBodyBytes, digitalSignature, publicKey)
	if err != nil || !verified {
		log.Println(err)
	}

	// deserialise request body
	var webhookRequest WebhookRequest
	err = json.Unmarshal(requestBodyBytes, &webhookRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println(err)
		return
	}

	// create response
	response := WebhookResponse{
		Nonce: webhookRequest.Nonce}

	responseJson, err := json.Marshal(response)
	if err != nil {
		fmt.Println(err)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseJson))
}

func loadPrivateKey() (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(authProfile.PrivateKeyPath)
	if err != nil {
		return nil, errors.New("no RSA private key found")
	}

	privPem, _ := pem.Decode(priv)
	if privPem.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("RSA private key is of the wrong type, Pem Type:" + privPem.Type)
	}
	privPemBytes := privPem.Bytes

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			return nil, errors.New("unable to parse RSA private key")
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("unable to parse RSA private key")
	}

	return privateKey, nil
}

func loadPublicKey() (*rsa.PublicKey, error) {
	pub, err := ioutil.ReadFile(authProfile.PublicKeyPath)
	if err != nil {
		return nil, errors.New("no RSA public key found")
	}

	pubPem, _ := pem.Decode(pub)
	if pubPem.Type != "PUBLIC KEY" {
		return nil, errors.New("RSA public key is of the wrong type, Pem Type:" + pubPem.Type)
	}
	pubPemBytes := pubPem.Bytes

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(pubPemBytes); err != nil {
		return nil, errors.New("unable to parse RSA public key")
	}

	var publicKey *rsa.PublicKey
	var ok bool
	publicKey, ok = parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unable to parse RSA public key")
	}

	return publicKey, nil
}
