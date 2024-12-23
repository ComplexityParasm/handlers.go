package main

import (
	"context"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"net/smtp"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
)

// Роли и разрешения
var rolesPermissions = map[string][]string{
	"Студент":       {"view_self_info", "view_courses"},
	"Преподаватель": {"view_courses", "grade_students"},
	"Админ":         {"manage_users", "manage_courses", "view_all_stats"},
}

// Структура для пользователя
type User struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// Хранилище пользователей
var users = map[string]string{
	"student@example.com": "password123",
	"teacher@example.com": "password456",
}

// Код подтверждения
var verificationCodes = make(map[string]string) // email -> verification code

// Redis context
var ctx = context.Background()

// Создание токена доступа
func createAccessToken(user User) (string, error) {
	permissions := getUserPermissions(user)
	claims := jwt.MapClaims{
		"sub":         user.Email,
		"permissions": permissions,
		"exp":         time.Now().Add(time.Minute * 5).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.SecretKey))
}

// Получение разрешений пользователя
func getUserPermissions(user User) []string {
	permissions := make(map[string]bool)
	for _, role := range user.Roles {
		if perms, exists := rolesPermissions[role]; exists {
			for _, p := range perms {
				permissions[p] = true
			}
		}
	}
	var permList []string
	for p := range permissions {
		permList = append(permList, p)
	}
	return permList
}

// Валидация токена
func validateToken(tokenString string) (jwt.Claims, error) {
	_, err := Rdb.Get(ctx, tokenString).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("token not found")
	} else if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.SecretKey), nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return token.Claims, nil
}

// Обработка аутентификации
func authenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		renderTemplate(w, "login.html", nil)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if storedPassword, exists := users[email]; exists && storedPassword == password {
		user := User{
			Email: email,
			Roles: []string{"Студент"}, // Можно добавить логику для установки ролей
		}
		token, err := createAccessToken(user)
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

// Защищенная функция
func protected(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "Authorization cookie is required", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value
	claims, err := validateToken(tokenStr)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	renderTemplate(w, "protected.html", map[string]string{"Email": claims.(jwt.MapClaims)["sub"].(string), "Token": tokenStr})
}

// Функция для рендеринга шаблонов
func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles("templates/" + tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}

// Страница выбора метода авторизации
func index(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "index.html", nil)
}

// Генерация случайного кода
func generateVerificationCode() string {
	rand.Seed(time.Now().UnixNano())
	code := fmt.Sprintf("%06d", rand.Intn(1000000)) // Генерируем 6-значный код
	return code
}

// Отправка email
func sendEmail(to string, code string) error {
	from := config.EmailFrom
	password := config.EmailPassword
	smtpHost := "smtp.gmail.com" // SMTP-сервер
	smtpPort := "587"            // Порт
	message := []byte("Subject: Код подтверждения\n" +
		"\nВаш код подтверждения: " + code)

	// Отправка email
	err := smtp.SendMail(smtpHost+":"+smtpPort, smtp.PlainAuth("", from, password, smtpHost), from, []string{to}, message)
	if err != nil {
		fmt.Println("Ошибка отправки email:", err) // Выводим информацию об ошибке
	}
	return err
}

// Обработчик для аутентификации через Яндекс
func yandexLoginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/yandex_login.html"))
	tmpl.Execute(w, nil)
}

// Обработчик для аутентификации через GitHub
func githubLoginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/github_login.html"))
	tmpl.Execute(w, nil)
}

// Обработка запроса кода
func requestCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Неправильный метод запроса", http.StatusMethodNotAllowed)
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
	code := generateVerificationCode()
	verificationCodes[email] = code

	if err := sendEmail(email, code); err != nil {
		http.Error(w, "Ошибка при отправке email", http.StatusInternalServerError)
		return
	}

	// Рендерим подтверждение
	renderTemplate(w, "code_sent.html", map[string]string{"Email": email})
}

// Обработка выхода
func logout(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:   "access_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Удаление кука
	}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/", http.StatusSeeOther) // Перенаправление на главную страницу
}
