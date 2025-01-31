package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"

	_ "github.com/lib/pq"
	"github.com/rs/cors"

	"github.com/gorilla/mux"

	"github.com/joho/godotenv"

	"golang.org/x/crypto/bcrypt"
)


func connectToDB() *sql.DB {
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: No .env file found")
	}

	connStr := os.Getenv("DATABASE_URL")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Error pinging database:", err)
	}
	return db
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashedPassword), err
}

func checkPassword(hashedPassword, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}
var secretKey = []byte("theSecretKey")



func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" || !strings.HasPrefix(tokenString, "Bearer") {
			http.Error(w, "missing or invalid token", http.StatusUnauthorized)
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error){
			return secretKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)

		if !ok {
			http.Error( w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		if exp, ok := claims["exp"].(float64); && int64(exp) < time.Now().Unix() {
			http.Error(w, "Token expired", http.STatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func generateJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp": time.Now().Add(time.Hour * 24).Unix(),


	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
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

	if !checkPassword(storedPassword, password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	tokenString, err := generate(username)
	if err != nil {
		http.Error(w, "Error creating JWT token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}


func uploadHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForum(10 << 20)
	if err != nil {
		http.Error(w, "Error parsing the form", http.StatusBadRequest)
		return
	}

	file, header, err := r.formFile("file")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileType := header.Header.Get("Content-Type")
	allowedTypes := map[string]bool{"image/png":true, "image/jpeg": true, "application/pdf": true}
	if !allowedTypes[fileType] {
		http.Error(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	safeFilename := fmt.Sprintf("file_%d%s", time.Now().Unix(), filepath.Ext(header.Filename))
	filePath := filepath.Join("./uploads/", safeFilename)

	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Error saving the file", http.StatusInternalServerERror)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst,file)
	if err != nil {
		http.Error(w, "Error saving the file", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("File uploaded successfully"))
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["fileID"]

	filePath := filepath.Join("./uploads/", fileID)
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Disposition", "attachment; filename="+fileID)
	w.Header().Set("Content-Type", "application/octet-stream")

	_, err = io.Copy(w, file)
	if err != nil {
		http.Error(w, "Error downloading the file", http.StatusInternalServerError)
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
	fmt.Printf("Server started at http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, handler))
}