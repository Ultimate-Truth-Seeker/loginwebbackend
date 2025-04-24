# Sistema de Autenticación con JWT - Frontend & Backend
Este proyecto es una aplicación web con autenticación mediante JWT. El frontend está construido con HTML, CSS y JavaScript, y el backend utiliza Node.js con Express. Permite a los usuarios iniciar sesión, visualizar su perfil protegido y cerrar sesión.
### Frontend:
- HTML5, CSS3
- JavaScript (Vanilla JS)
- Fetch API

### Backend:
- Go
- JSON Web Tokens (JWT)
- CORS
- dotenv
- SQLite

### Estructura del Proyecto
```
├── frontend/
│   ├── index.html
│   ├── register.html
│   ├── profile.html
│   ├── login.js
│   ├── register.js
│   └── profile.js
├── backend/
│   ├── cors.go
│   ├── database.go
│   ├── main.go
│   ├── handlers/
│   └── models/
```

### Instalación del proyecto
Para configurar la base de datos

En la carpeta del backend ejecutar desde la terminal:

`sqlite3 users.db`

y dentro de la shell de sqlite: 

`.tables`

`.schema users`

Si sale la información de la tabla de usuarios no hay que hacer nada más, sino ejecutar estos comandos para crear la tabla:

`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);`

`CREATE TABLE active_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE, 
    expires_at DATETIME NOT NULL,
    isActive BOOLEAN,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);`

`CREATE INDEX idx_active_tokens_token_hash ON active_tokens(token_hash);`

Verificar nuevamente .tables y .schema users, y para salir:

`.quit`

Para configurar el backend

Ejecutar estos comandos para obtener las librerías:

`go get github.com/go-chi/cors`

`go get github.com/golang-jwt/jwt/v5`

Para iniciar el backend:

`go mod tidy`

`go run .`

Y debería de correr en el puerto :3000 de localhost

Para el frontend unicamente es necesario abrir index.html en el navegador, si los demas archivos del frontend estan en la misma carpeta que el index. 

Desarrollado por [Ultimate-Truth-Seeker]


