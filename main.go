package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type App struct {
	db   *sql.DB
	tmpl *template.Template
}

type User struct {
	ID    int64
	Email string
}

func main() {
	dbPath := getenv("DB_PATH", "./app.db")
	addr := getenv("ADDR", ":8080")

	db, err := sql.Open("sqlite", dbPath)
	must(err)
	must(db.Ping())

	must(migrate(db))

	tmpl := template.Must(template.ParseGlob("templates/*.html"))
	app := &App{db: db, tmpl: tmpl}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/resource", app.handleResource)        // ?id=1
	mux.HandleFunc("/resource/new", app.handleNewResource) // GET/POST
	mux.HandleFunc("/resource/comment", app.handleComment) // POST
	mux.HandleFunc("/register", app.handleRegister)        // GET/POST
	mux.HandleFunc("/login", app.handleLogin)              // GET/POST
	mux.HandleFunc("/logout", app.handleLogout)            // POST/GET

	// Sécurité basique + logs
	handler := loggingMiddleware(securityHeaders(mux))

	log.Printf("Listening on %s (db=%s)", addr, dbPath)
	must(http.ListenAndServe(addr, handler))
}

func migrate(db *sql.DB) error {
	stmts := []string{
		`PRAGMA foreign_keys = ON;`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			expires_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS resources (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			url TEXT NOT NULL,
			description TEXT NOT NULL,
			created_by INTEGER NOT NULL REFERENCES users(id),
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS comments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			content TEXT NOT NULL,
			label TEXT NOT NULL CHECK (label IN ('recommended','obsolete')),
			created_at TEXT NOT NULL
		);`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	user, _ := a.currentUser(r)

	rows, err := a.db.Query(`
		SELECT id, title, url, description, created_at
		FROM resources
		ORDER BY id DESC
		LIMIT 100;
	`)
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	defer rows.Close()

	type Res struct {
		ID          int64
		Title       string
		URL         string
		Description string
		CreatedAt   string
	}
	var items []Res
	for rows.Next() {
		var it Res
		must(rows.Scan(&it.ID, &it.Title, &it.URL, &it.Description, &it.CreatedAt))
		items = append(items, it)
	}

	data := map[string]any{
		"User":  user,
		"Items": items,
	}
	a.render(w, "index.html", data)
}

func (a *App) handleResource(w http.ResponseWriter, r *http.Request) {
	user, _ := a.currentUser(r)

	idStr := r.URL.Query().Get("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id <= 0 {
		http.NotFound(w, r)
		return
	}

	type Res struct {
		ID          int64
		Title       string
		URL         string
		Description string
		CreatedAt   string
	}
	var res Res
	err := a.db.QueryRow(`
		SELECT id, title, url, description, created_at
		FROM resources WHERE id = ?;
	`, id).Scan(&res.ID, &res.Title, &res.URL, &res.Description, &res.CreatedAt)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	type C struct {
		Email     string
		Content   string
		Label     string
		CreatedAt string
	}
	rows, err := a.db.Query(`
		SELECT u.email, c.content, c.label, c.created_at
		FROM comments c
		JOIN users u ON u.id = c.user_id
		WHERE c.resource_id = ?
		ORDER BY c.id DESC
		LIMIT 200;
	`, id)
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	defer rows.Close()

	var comments []C
	for rows.Next() {
		var c C
		must(rows.Scan(&c.Email, &c.Content, &c.Label, &c.CreatedAt))
		comments = append(comments, c)
	}

	data := map[string]any{
		"User":     user,
		"Resource": res,
		"Comments": comments,
	}
	a.render(w, "resource.html", data)
}

func (a *App) handleNewResource(w http.ResponseWriter, r *http.Request) {
	user, ok := a.requireAuth(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		a.render(w, "new_resource.html", map[string]any{"User": user})
	case http.MethodPost:
		title := strings.TrimSpace(r.FormValue("title"))
		url := strings.TrimSpace(r.FormValue("url"))
		desc := strings.TrimSpace(r.FormValue("description"))

		if title == "" || url == "" || desc == "" {
			a.render(w, "new_resource.html", map[string]any{
				"User":  user,
				"Error": "Tous les champs sont obligatoires.",
			})
			return
		}
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

		_, err := a.db.Exec(`
			INSERT INTO resources (title, url, description, created_by, created_at)
			VALUES (?, ?, ?, ?, ?);
		`, title, url, desc, user.ID, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			http.Error(w, "db error", 500)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (a *App) handleComment(w http.ResponseWriter, r *http.Request) {
	user, ok := a.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	resID, _ := strconv.ParseInt(r.FormValue("resource_id"), 10, 64)
	content := strings.TrimSpace(r.FormValue("content"))
	label := r.FormValue("label")

	if resID <= 0 || content == "" || (label != "recommended" && label != "obsolete") {
		http.Redirect(w, r, "/resource?id="+strconv.FormatInt(resID, 10), http.StatusSeeOther)
		return
	}

	_, err := a.db.Exec(`
		INSERT INTO comments (resource_id, user_id, content, label, created_at)
		VALUES (?, ?, ?, ?, ?);
	`, resID, user.ID, content, label, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	http.Redirect(w, r, "/resource?id="+strconv.FormatInt(resID, 10), http.StatusSeeOther)
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.render(w, "register.html", nil)
	case http.MethodPost:
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		pass := r.FormValue("password")
		if email == "" || pass == "" || len(pass) < 8 {
			a.render(w, "register.html", map[string]any{"Error": "Email requis et mot de passe >= 8 caractères."})
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		_, err := a.db.Exec(`
			INSERT INTO users (email, password_hash, created_at)
			VALUES (?, ?, ?);
		`, email, string(hash), time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			a.render(w, "register.html", map[string]any{"Error": "Compte déjà existant ou erreur."})
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.render(w, "login.html", nil)
	case http.MethodPost:
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		pass := r.FormValue("password")

		var id int64
		var hash string
		err := a.db.QueryRow(`SELECT id, password_hash FROM users WHERE email = ?;`, email).Scan(&id, &hash)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
			a.render(w, "login.html", map[string]any{"Error": "Identifiants invalides."})
			return
		}

		token := randomToken(32)
		expires := time.Now().Add(14 * 24 * time.Hour).UTC()

		_, err = a.db.Exec(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?);`,
			token, id, expires.Format(time.RFC3339))
		if err != nil {
			http.Error(w, "db error", 500)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   isProd(),
			Expires:  expires,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err == nil && c.Value != "" {
		_, _ = a.db.Exec(`DELETE FROM sessions WHERE token = ?;`, c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) currentUser(r *http.Request) (*User, error) {
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" {
		return nil, errors.New("no session")
	}

	var userID int64
	var expiresAt string
	err = a.db.QueryRow(`SELECT user_id, expires_at FROM sessions WHERE token = ?;`, c.Value).
		Scan(&userID, &expiresAt)
	if err != nil {
		return nil, err
	}
	exp, _ := time.Parse(time.RFC3339, expiresAt)
	if time.Now().UTC().After(exp) {
		return nil, errors.New("expired")
	}

	var u User
	err = a.db.QueryRow(`SELECT id, email FROM users WHERE id = ?;`, userID).Scan(&u.ID, &u.Email)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (a *App) requireAuth(w http.ResponseWriter, r *http.Request) (*User, bool) {
	u, err := a.currentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, false
	}
	return u, true
}

func (a *App) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := a.tmpl.ExecuteTemplate(w, name, data)
	if err != nil {
		http.Error(w, "template error", 500)
	}
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func isProd() bool {
	return os.Getenv("RENDER") == "true" || os.Getenv("ENV") == "prod"
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
