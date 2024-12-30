package main

import (
	"fmt"
	"go-auth/handlers"
	"log"
	"net/http"
)

func main() {
	// Регистрация маршрутов
	http.HandleFunc("/", handlers.IndexHandler)
	http.HandleFunc("/login", handlers.AuthenticateHandler)
	http.HandleFunc("/auth-code-request", handlers.RequestCodeHandler)
	http.HandleFunc("/code-authentication", handlers.CodeAuthenticationHandler)
	http.HandleFunc("/auth-status", handlers.AuthStatusHandler)
	http.HandleFunc("/success-login", handlers.HandleSuccessLogin)
	http.HandleFunc("/auth/github", handlers.GithubLoginHandler)
	http.HandleFunc("/auth/yandex", handlers.YandexLoginHandler)

	fmt.Println("Go server is running on port 8081")
	err := http.ListenAndServe(":8081", nil)
	if err != nil {
		log.Fatal("Failed to start Go server", err)
	}
}
