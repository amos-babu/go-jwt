package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

var secretKey = []byte("secret-key")

type User struct {
	Username string `json:"username"`
	Pasword  string `json:"password"`
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/protected", ProtectedHandler).Methods("GET")

	fmt.Println("Starting the server")
	if err := http.ListenAndServe("localhost:4000", r); err != nil {
		fmt.Println("Could not start the server", err)
	}
}

// Creating and signing new JWT
func createToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, err
}

// Verifying available JWT Tokens before granting access
func verifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("Invalid token")
	}
	return nil
}

// Implementing a Login System
func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var u User
	json.NewDecoder(r.Body).Decode(&u)
	fmt.Printf("The user request value %v", u)

	if u.Username == "Chek" && u.Pasword == "123456" {
		tokenString, err := createToken(u.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Errorf("No username found")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, tokenString)
		return
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid credentials")
	}
}

// Securing Protected Routes
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")

	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Missing authorization header")
		return
	}

	tokenString = tokenString[len("Bearer "):]

	if err := verifyToken(tokenString); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid token")
		return
	}

	fmt.Fprint(w, "Welcome to the the protected area")
}
