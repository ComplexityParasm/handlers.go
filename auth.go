package auth

import (
	"context"
	"fmt"
	"math/rand"
	"net/smtp"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
)

type Config struct {
	RedisAddr     string
	RedisPassword string
	SecretKey     string
	EmailFrom     string
	EmailPassword string
}

func (auth *Config) CreateAccessToken(user User) (string, error) {
	// Логика создания токена
	permissions := getUserPermissions(user)
	claims := jwt.MapClaims{
		"sub":         user.Email,
		"permissions": permissions,
		"exp":         time.Now().Add(time.Minute * 5).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(auth.SecretKey)) //TODO: Use Config
}

// Функция для генерации случайного кода
func (auth *Config) generateVerificationCode() string {
	rand.Seed(time.Now().UnixNano())
	code := fmt.Sprintf("%06d", rand.Intn(1000000)) // Генерируем 6-значный код
	return code
}

// Функция для отправки email
func (auth *Config) sendEmail(to string, code string) error {
	from := auth.EmailFrom
	password := auth.EmailPassword
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

func (auth *Config) GetRedisClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     auth.RedisAddr,
		Password: auth.RedisPassword,
		DB:       0,
	})
}
func NewAuthConfig() *Config {
	return &Config{
		RedisAddr:     "localhost:6379", //TODO: Read from env
		RedisPassword: "",
		SecretKey:     "your_secret_key", //TODO: Read from env
		EmailFrom:     "example@gmail.com",
		EmailPassword: "password",
	}
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

// Структура для пользователя
type User struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// Роли и разрешения
var rolesPermissions = map[string][]string{
	"Студент":       {"view_self_info", "view_courses"},
	"Преподаватель": {"view_courses", "grade_students"},
	"Админ":         {"manage_users", "manage_courses", "view_all_stats"},
}

// Код подтверждения
var verificationCodes = make(map[string]string)
var ctx = context.Background()

type CodeInfo struct {
	Token      string    // Токен входа (для авторизации)
	Expiration time.Time // Время истечения срока действия кода
}
type AuthInfo struct {
	Expiration time.Time
	Status     string
}

var codeStorage = make(map[string]CodeInfo)
var authStorage = make(map[string]AuthInfo)

func (auth *Config) saveCode(code string, token string) {
	codeStorage[code] = CodeInfo{
		Token:      token,
		Expiration: time.Now().Add(time.Minute),
	}
}
func (auth *Config) saveAuthInfo(token string) {
	authStorage[token] = AuthInfo{
		Expiration: time.Now().Add(time.Minute * 5),
		Status:     "Not Recived",
	}
}
func (auth *Config) validateCode(code string, refreshToken string) (string, bool, error) {
	codeInfo, ok := codeStorage[code]
	if !ok {
		return "", false, fmt.Errorf("code not found")
	}
	if time.Now().After(codeInfo.Expiration) {
		delete(codeStorage, code)
		return "", false, fmt.Errorf("code expired")
	}
	_, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(auth.SecretKey), nil //TODO: Use Config
	})
	if err != nil {
		return "", false, fmt.Errorf("token is not valid")
	}
	delete(codeStorage, code)
	return codeInfo.Token, true, nil
}
func (auth *Config) validateAuthInfo(token string) (bool, error) {
	authInfo, ok := authStorage[token]
	if !ok {
		return false, fmt.Errorf("token not found")
	}
	if time.Now().After(authInfo.Expiration) {
		delete(authStorage, token)
		return false, fmt.Errorf("token expired")
	}
	return true, nil
}
func (auth *Config) updateAuthInfo(token string, status string) {
	authInfo, ok := authStorage[token]
	if !ok {
		fmt.Println("token not found")
		return
	}
	authInfo.Status = status
	authStorage[token] = authInfo
}

// Обработчик запроса по коду (через Authorization Server)
func (auth *Config) HandleCodeAuthentication(code string, refreshToken string) (string, bool, error) {
	token, ok, err := auth.validateCode(code, refreshToken)
	if !ok {
		return "", false, err
	}
	return token, true, nil
}
func (auth *Config) HandleAuthCodeRequest(token string) (string, error) {
	// сохраняем token auth
	auth.saveAuthInfo(token)
	code := auth.generateVerificationCode()
	auth.saveCode(code, token)
	return code, nil
}
