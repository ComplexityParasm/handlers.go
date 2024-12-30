package main

import (
	"encoding/json"
	"fmt"
	"go-auth/auth"
	"html/template"
	"log"
	"net/http"
)

// Хранилище пользователей
var users = map[string]string{
	"student@example.com": "password123",
	"teacher@example.com": "password456",
}

type AuthResponse struct {
	Code string `json:"code"`
}
type CodeResponse struct {
	Token   string `json:"token"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderTemplate(w, "login.html", nil)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if storedPassword, exists := users[email]; exists && storedPassword == password {
		user := auth.User{
			Email: email,
			Roles: []string{"Студент"}, // Можно добавить логику для установки ролей
		}

		authConfig := auth.NewAuthConfig()
		token, err := authConfig.CreateAccessToken(user)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Создание кука с токеном
		cookie := http.Cookie{
			Name:     "access_token",
			Value:    token,
			Path:     "/",
			MaxAge:   300, // Срок действия кука в секундах (5 минут)
			HttpOnly: true,
		}
		http.SetCookie(w, &cookie)

		// Отправка ответа
		renderTemplate(w, "protected.html", map[string]string{
			"Email": email,
			"Token": token,
		})
	} else {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
	}
}

func requestCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Неправильный метод запроса", http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "token must be provided", http.StatusBadRequest)
		return
	}
	// Проверяем, есть ли email
	email := r.URL.Query().Get("email")
	if email == "" {
		// Если email не указан, рендерим форму
		renderTemplate(w, "request_code.html", nil)
		return
	}

	// Генерация и отправка кода
	authConfig := auth.NewAuthConfig()
	code, err := authConfig.HandleAuthCodeRequest(token)

	if err != nil {
		http.Error(w, "Ошибка при отправке email", http.StatusInternalServerError)
		return
	}

	jsonResponse, _ := json.Marshal(AuthResponse{Code: code})

	// Рендерим подтверждение
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}
func codeAuthentication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Неправильный метод запроса", http.StatusMethodNotAllowed)
		return
	}
	// Проверяем, есть ли code
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code must be provided", http.StatusBadRequest)
		return
	}
	refreshToken := r.URL.Query().Get("refreshToken")
	if refreshToken == "" {
		http.Error(w, "refresh token must be provided", http.StatusBadRequest)
		return
	}
	authConfig := auth.NewAuthConfig()
	token, ok, err := authConfig.HandleCodeAuthentication(code, refreshToken)

	var jsonResponse []byte
	if !ok {
		message := "token is not valid"
		if err != nil {
			message = err.Error()
		}
		jsonResponse, _ = json.Marshal(CodeResponse{
			Token:   "",
			Success: false,
			Message: message,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonResponse)
		return
	}

	jsonResponse, _ = json.Marshal(CodeResponse{
		Token:   token,
		Success: true,
		Message: "success",
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}
func authStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Неправильный метод запроса", http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "token must be provided", http.StatusBadRequest)
		return
	}
	authConfig := auth.NewAuthConfig()
	ok, err := authConfig.ValidateAuthInfo(token)
	if err != nil {
		http.Error(w, "token is not valid", http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "token is expired", http.StatusBadRequest)
		return
	}
	authConfig.UpdateAuthInfo(token, "received")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("token status updated"))
}
func handleSuccessLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "token must be provided", http.StatusBadRequest)
		return
	}
	authConfig := auth.NewAuthConfig()
	_, err := authConfig.ValidateAuthInfo(token)
	if err != nil {
		http.Error(w, "token not valid", http.StatusBadRequest)
		return
	}
	renderTemplate(w, "protected.html", map[string]string{
		"Token": token,
	})
}

// для входа через гитхаб
func github_login(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "github_login.html", nil)
}

func yandexLoginHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "yandex_login.html", nil)
}

// Функция для рендеринга шаблонов
func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles("../templates/" + tmpl) // Измененный путь
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}
func index(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "index.html", nil)
}
func main() {
	// Регистрация маршрутов
	http.HandleFunc("/", index)
	http.HandleFunc("/login", authenticate)
	http.HandleFunc("/auth-code-request", requestCodeHandler)
	http.HandleFunc("/code-authentication", codeAuthentication)
	http.HandleFunc("/auth-status", authStatus)
	http.HandleFunc("/success-login", handleSuccessLogin)
	http.HandleFunc("/auth/github", github_login)
	http.HandleFunc("/auth/yandex", yandexLoginHandler)

	fmt.Println("Go server is running on port 8081")
	err := http.ListenAndServe(":8081", nil) // Запускаем сервер на порту 8081
	if err != nil {
		log.Fatal("Failed to start Go server", err)
	}
}
