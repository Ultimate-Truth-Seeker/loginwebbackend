package main

import (
    "database/sql"
    "encoding/json"

    "log"
    "net/http"
	"myapp/handlers"
    "myapp/models"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
)

func main() {
    db, err := setupDatabase("./users.db")
    // ... (manejo de error db) ...
    if err != nil {
        log.Fatal("CRITICAL: No se pudo conectar a la base de datos:", err)
    }
    defer db.Close()

    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)
    r.Use(configureCORS()) // CORS primero

    // --- Rutas Públicas ---
    r.Route("/auth", func(r chi.Router) {
         r.Post("/register", handlers.PostRegisterHandler(db)) // Mover register aquí
         r.Post("/login", handlers.PostLoginHandler(db))    // Mover login aquí
    })
    r.Get("/", func(w http.ResponseWriter, r *http.Request) { /* ... */ })


    // --- Rutas Protegidas ---
    r.Group(func(r chi.Router) {
        // Aplicar middleware JWT a este grupo
        r.Use(handlers.JwtAuthMiddleware(db))

        // Rutas que requieren token válido
        r.Post("/auth/logout", handlers.PostLogoutHandler(db)) // Mover logout aquí
        r.Get("/users/profile", getUserHandler(db)) // Nueva ruta para perfil
        // La ruta /users/{userID} podría seguir siendo pública o protegerse también
        // r.Get("/users/{userID}", getUserHandler(db)) // Ejemplo si se protege
    })

    // (Opcional: Mantener /users/{userID} pública si se desea)
     r.Get("/users/{userID}", getUserHandler(db))


    port := ":3000"
    log.Printf("Servidor escuchando en puerto %s", port)
    log.Fatal(http.ListenAndServe(port, r))
}


// --- Nuevo Handler para Perfil ---
// (Podría ir en users.go o un nuevo profile.go)
func getUserHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
         // Obtener userID del contexto (inyectado por el middleware)
         userID, ok := r.Context().Value("userID").(int)
         if !ok || userID == 0 {
             http.Error(w, `{"error": "No se pudo obtener ID de usuario del token"}`, http.StatusInternalServerError)
             return
         }

         // Ahora usar este userID para buscar los datos del perfil
         var userResp models.LoginSuccessData
         err := db.QueryRow("SELECT id, username FROM users WHERE id = ?", userID).Scan(&userResp.UserID, &userResp.Username)
         if err != nil {
             // ... (manejo de error: 404 si no se encuentra, 500 otros) ...
             if err == sql.ErrNoRows {
                 http.Error(w, `{"error": "Usuario del token no encontrado"}`, http.StatusNotFound)
             } else {
                 log.Printf("Error consultando perfil para user %d: %v", userID, err)
                 http.Error(w, `{"error": "Error interno del servidor"}`, http.StatusInternalServerError)
             }
             return
         }

         w.Header().Set("Content-Type", "application/json")
         json.NewEncoder(w).Encode(userResp)
    }
}
