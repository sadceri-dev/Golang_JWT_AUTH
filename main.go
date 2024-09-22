package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	UserID   uint   `db:"user_id"`
	Email    string `db:"email"`
	Password string `db:"password"`
}

type RefreshToken struct {
	ID             uint      `db:"rt_id"`
	UserID         uint      `db:"user_id"`
	TokenHash      string    `db:"tokenHash"`
	AccessTokenJTI string    `db:"accessToken_jti"`
	UserIP         string    `db:"user_ip"`
	Expiration     time.Time `db:"expiration"`
}

var secretKey = []byte("secret-phrase")

type Claims struct {
	UserID uint   `json:"user_id"`
	UserIP string `json:"user_ip"`
	jwt.StandardClaims
}

func createAccessToken(userID uint, userIP string) (string, string, error) {

	jti := uuid.New().String()

	expirationTime := time.Now().Add(3 * time.Hour)

	claims := &Claims{
		UserID: userID,
		UserIP: userIP,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Id:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}

func createRefreshToken(length int) (string, string, error) {
	tokenBytes := make([]byte, length)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	refreshToken := base64.URLEncoding.EncodeToString(tokenBytes)

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return refreshToken, string(hashedToken), nil
}

func saveRefreshToken(db *sql.DB, userID uint, jti, tokenHash, userIP string) error {
	expiration := time.Now().Add(3 * 24 * time.Hour)
	_, err := db.Exec(
		"INSERT INTO refreshtoken (user_id, tokenHash, accessToken_jti, user_ip, expiration) VALUES ($1, $2, $3, $4, $5)",
		userID, tokenHash, jti, userIP, expiration,
	)
	return err
}

func validateRefreshToken(refreshToken string, storedHash string) error {
	return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(refreshToken))
}

func handleTokenRequest(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	userID := r.URL.Query().Get("user_id")
	ip := getUserIP(r)

	accessToken, jti, err := createAccessToken(uint(userID), ip)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, hashedRefreshToken, err := createRefreshToken(32)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	err = saveRefreshToken(db, uint(userID), jti, hashedRefreshToken, ip)
	if err != nil {
		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "AccessToken: %s\nRefreshToken: %s\n", accessToken, refreshToken)
}

func getUserIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func handleRefreshRequest(w http.ResponseWriter, r *http.Request, db *sql.DB) {

	accessToken := r.URL.Query().Get("access_token")
	refreshToken := r.URL.Query().Get("refresh_token")

	claims := &Claims{}
	_, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	var storedToken RefreshToken
	err = db.QueryRow(
		"SELECT rt_id, user_id, tokenHash, accessToken_jti, user_ip FROM refreshtoken WHERE accessToken_jti = $1",
		claims.Id,
	).Scan(&storedToken.ID, &storedToken.UserID, &storedToken.TokenHash, &storedToken.AccessTokenJTI, &storedToken.UserIP)
	if err != nil {
		http.Error(w, "Refresh token not found", http.StatusUnauthorized)
		return
	}

	err = validateRefreshToken(refreshToken, storedToken.TokenHash)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	ip := getUserIP(r)
	if ip != storedToken.UserIP {
		err := sendEmailWarning(userEmail, storedToken.UserIP, ip)
		if err != nil {
			log.Printf("Failed to send email warning: %v", err)
		}
		log.Printf("Warning: IP address mismatch for user %d. Old: %s, New: %s", storedToken.UserID, storedToken.UserIP, ip)
	}

	newAccessToken, _, err := createAccessToken(storedToken.UserID, ip)
	if err != nil {
		http.Error(w, "Failed to generate new access token", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "New AccessToken: %s\n", newAccessToken)
}

func sendEmailWarning(toEmail, userIP, newIP string) error {
	smtpHost := "host.server.ru"
	smtpPort := "5555"
	smtpUsername := "admin_email@example.com"
	smtpPassword := "admin_password"

	from := smtpUsername
	to := []string{toEmail}

	subject := "Warning: IP Address Changed"
	body := fmt.Sprintf("Your IP address has changed from %s to %s. If this was not you, please contact support.", userIP, newIP)
	msg := "From: " + from + "\n" +
		"To: " + toEmail + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, []byte(msg))
	if err != nil {
		return err
	}
	return nil
}

func main() {
	connDB := "postgresql://uxy0iy0m8lx7gvf0e7ez:Xx0ZRH7WTw5q946BFbAtXACkcvOM9U@bmrnwlzxk18ngjqtje7b-postgresql.services.clever-cloud.com:50013/bmrnwlzxk18ngjqtje7b"
	db, err := sql.Open("postgres", connDB)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		handleTokenRequest(w, r, db)
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		handleRefreshRequest(w, r, db)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
