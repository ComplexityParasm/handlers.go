package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-redis/redis/v8"
)

// Config структура для хранения конфигурации
type Config struct {
	RedisAddr     string
	RedisPassword string
	SecretKey     string
	EmailFrom     string
	EmailPassword string
	Port          string
}

var config Config

func loadConfig() {
	config = Config{
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		SecretKey:     getEnv("SECRET_KEY", "your_secret_key"),
		EmailFrom:     getEnv("EMAIL_FROM", "example@gmail.com"),
		EmailPassword: getEnv("EMAIL_PASSWORD", "password"),
		Port:          getEnv("PORT", "8080"),
	}
}

func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

var Rdb *redis.Client

func initRedis() {
	Rdb = redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       0,
	})
}

func main() {
	loadConfig() // Загрузка конфигурации
	initRedis()  // Инициализация Redis

	// Регистрация маршрутов (пусть функции-обработчики определены в handlers.go)
	http.HandleFunc("/", index)
	http.HandleFunc("/login", authenticate)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.HandleFunc("/request-code", requestCodeHandler)
	http.HandleFunc("/auth/yandex", yandexLoginHandler)
	http.HandleFunc("/auth/github", githubLoginHandler)

	fmt.Printf("Server is running on port %s\n", config.Port)
	err := http.ListenAndServe(":"+config.Port, nil)
	if err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}
