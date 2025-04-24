package handlers

import (
    "context"
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

var jwtSecretKey = []byte("mi_clave_secreta_muy_segura_cambiar_esto")

func GenerateJWT(userID int) (string, time.Time, error) {
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := jwt.RegisteredClaims{
        Subject:   fmt.Sprintf("%d", userID),
        ExpiresAt: jwt.NewNumericDate(expirationTime),
        IssuedAt:  jwt.NewNumericDate(time.Now()),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtSecretKey)
    if err != nil {
        return "", time.Time{}, err
    }

    return tokenString, expirationTime, nil
}

func HashToken(token string) string {
    hasher := sha256.New()
    hasher.Write([]byte(token))
    return hex.EncodeToString(hasher.Sum(nil))
}

func StoreToken(db *sql.DB, userID int, token string, expiresAt time.Time) error {
    tokenHash := HashToken(token)
    stmt, err := db.Prepare("INSERT INTO active_tokens(user_id, token_hash, expires_at) VALUES(?, ?, ?)")
    if err != nil {
        return fmt.Errorf("error preparando statement: %w", err)
    }
    defer stmt.Close()
    _, err = stmt.Exec(userID, tokenHash, expiresAt)
    return err
}

func InvalidateToken(db *sql.DB, token string) error {
    tokenHash := HashToken(token)
    stmt, err := db.Prepare("DELETE FROM active_tokens WHERE token_hash = ?")
    if err != nil {
        return fmt.Errorf("error preparando statement: %w", err)
    }
    defer stmt.Close()
    result, err := stmt.Exec(tokenHash)
    if err != nil {
        return fmt.Errorf("error ejecutando delete: %w", err)
    }
    if rows, _ := result.RowsAffected(); rows == 0 {
        log.Printf("Token no encontrado o ya eliminado (hash: %s...)", tokenHash[:10])
    } else {
        log.Printf("Token invalidado exitosamente (hash: %s...)", tokenHash[:10])
    }
    return nil
}

func ValidateTokenAndGetUserID(db *sql.DB, tokenString string) (int, error) {
    claims := &jwt.RegisteredClaims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["alg"])
        }
        return jwtSecretKey, nil
    })

    if err != nil {
        if errors.Is(err, jwt.ErrTokenExpired) {
            log.Println("Token expirado:", err)
            go func() {
                _ = CleanupExpiredToken(db, tokenString)
            }()
        }
        return 0, fmt.Errorf("error parseando token: %w", err)
    }

    if !token.Valid {
        return 0, errors.New("token inválido")
    }

    tokenHash := HashToken(tokenString)
    var dbUserID int
    var expiresAt time.Time
    err = db.QueryRow("SELECT user_id, expires_at FROM active_tokens WHERE token_hash = ?", tokenHash).Scan(&dbUserID, &expiresAt)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return 0, errors.New("token no activo en DB")
        }
        return 0, fmt.Errorf("error consultando DB: %w", err)
    }

    if time.Now().After(expiresAt) {
        go func() {
            _ = CleanupExpiredToken(db, tokenString)
        }()
        return 0, errors.New("token expirado (verificado en DB)")
    }

    // Extraer el userID desde claims.Subject
    var parsedUserID int
    if claims.Subject != "" {
        _, err := fmt.Sscanf(claims.Subject, "%d", &parsedUserID)
        if err != nil || parsedUserID != dbUserID {
            return 0, errors.New("userID no coincide entre claims y DB")
        }
        return parsedUserID, nil
    }

    return 0, errors.New("subject vacío en token")
}

func JwtAuthMiddleware(db *sql.DB) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "Falta header de autorización", http.StatusUnauthorized)
                return
            }

            parts := strings.Split(authHeader, " ")
            if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
                http.Error(w, "Formato inválido (se espera 'Bearer <token>')", http.StatusUnauthorized)
                return
            }

            tokenString := parts[1]
            userID, err := ValidateTokenAndGetUserID(db, tokenString)
            if err != nil {
                log.Printf("Error autenticando token: %v", err)
                http.Error(w, "Token inválido o expirado", http.StatusUnauthorized)
                return
            }

            ctx := context.WithValue(r.Context(), "userID", userID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

func CleanupExpiredToken(db *sql.DB, tokenString string) error {
    tokenHash := HashToken(tokenString)
    _, err := db.Exec("DELETE FROM active_tokens WHERE token_hash = ?", tokenHash)
    if err != nil && err != sql.ErrNoRows {
        return fmt.Errorf("error eliminando token expirado (hash: %s): %w", tokenHash[:10], err)
    }
    log.Printf("Token expirado limpiado de DB (hash: %s...)", tokenHash[:10])
    return nil
}