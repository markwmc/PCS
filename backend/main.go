package main

import (
	
	"fmt"
	"log"
	"net/http"
	"database/sql"
	"time"
	"io"
	"encoding/json"
	"os"
	"github.com/golang-jwt/jwt"
	"strings"

	_ "github.com/lib/pq"
	"github.com/rs/cors"
	
	"github.com/gorilla/mux"

	
	

	
)
var secretKey = []byte("theSecretKey")

func connectToDB() *sql.DB {
	connStr := "user=user password=password dbname=personal_cloud sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Error pinging database", err)
	}
	return db
}

func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(tokenString, "Bearer ") {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		tokenString = tokenString[len("Bearer "):]
		
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error){
			return secretKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	r.ParseForm()

	username := r.FormValue("username")
	password := r.FormValue("password")

	var storedPassword string
	query := "SELECT password FROM users WHERE username = $1"
	err := db.QueryRow(query, username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
		} else {
			http.Error(w, "error accessing database", http.StatusInternalServerError)
		}
		return
	}

	if storedPassword == password {
		tokenString, err := generateJWT(username)
		if err != nil {
			http.Error(w, "Error creating JWT token", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"token": tokenString,
		})
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

func generateJWT(username string) (string, error) {
	claims := jwt.MapClaims{}
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)

	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Error parsing the form", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filePath := "./uploads/" + "file_" + fmt.Sprintf("%d", time.Now().Unix()) + ".txt"
	dst, err := os.Create(filePath)

	if err != nil {
		http.Error(w, "Error saving the file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Error saving the file", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("File uploaded successfully"))
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	fileID := strings.TrimPrefix(r.URL.Path, "/download/")

	filePath := "./uploads/" + fileID

	file, err := os.Open(filePath)

	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Disposition", "attachment; filename="+fileID)
	w.Header().Set("Content-Type", "application/octet-stream")

	_, err = io.Copy(w, file)
	if err != nil {
		http.Error(w, "Error downloading the file", http.StatusInternalServerError)
		return
	}

}

func proxyToExternalAPI(w http.ResponseWriter, r *http.Request) {
	externalURL := "https://github.dev/pf-signin?id=interesting-chair-7ld42sd&cluster=use&name=refactored-fiesta-465v4w7vpr62jvqr&port=8100"

	resp, err := http.Get(externalURL)
	if err != nil {
		http.Error(w, "Error making request to external api", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, "Error sending response", http.StatusInternalServerError)
		return
	}

}


func main() {

	db := connectToDB()
	defer db.Close()

	r := mux.NewRouter()

	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r, db)}).Methods("POST")
	r.HandleFunc("/upload", uploadHandler).Methods("POST")
	r.HandleFunc("/download/{fileID}", downloadHandler).Methods("GET")
	r.HandleFunc("/proxy", proxyToExternalAPI).Methods("GET")

	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:8100","http://localhost:8080", "https://refactored-fiesta-465v4w7vpr62jvqr-8100.app.github.dev"},
		AllowedMethods: []string{"GET", "POST", "PUT","DELETE"},
		AllowedHeaders: []string{"Authorization", "Content-Type", "Access-Control-Allow-Origin"},
	})

	protectedRoutes := r.PathPrefix("/protected").Subrouter()
	protectedRoutes.Use(jwtMiddleware)
	protectedRoutes.HandleFunc("/upload", uploadHandler).Methods("POST")
	protectedRoutes.HandleFunc("/download/{fileID}", downloadHandler).Methods("GET")
	
	handler := corsHandler.Handler(r)

	port := ":8080"
	fmt.Printf("Server started at http://localhost/%s\n", port)
	log.Fatal(http.ListenAndServe(port, handler))
}