package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	"net/http"
	"time"
)

type app struct {
	db *sql.DB
}

var templates *template.Template

func newSessionID() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func runMigrations(db *sql.DB) error {
	driver, err := mysql.WithInstance(db, &mysql.Config{})
	if err != nil {
		return fmt.Errorf("create migrate driver: %w", err)
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"mysql",
		driver,
	)
	if err != nil {
		return fmt.Errorf("create migrate instance: %w", err)
	}

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("apply migrations: %w", err)
	}

	return nil
}

type User struct {
	ID             int    `json:"id"`
	Email          string `json:"email"`
	SubscriptionID *int   `json:"subscription_id"`
}

func HashPasswordDeterministic(password, secret string) ([]byte, error) {

	return bcrypt.GenerateFromPassword([]byte(password+secret), bcrypt.DefaultCost)
}

func CheckPasswordDeterministic(password, secret string, hashed []byte) error {
	return bcrypt.CompareHashAndPassword(hashed, []byte(password+secret))
}

func (a *app) homePageHandler(w http.ResponseWriter, r *http.Request) {
	session_id, err := r.Cookie("db_session_id")

	if err != nil || session_id.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	log.Println(session_id.Value)
	var user_id int
	var expires_at time.Time
	now := time.Now()

	err = a.db.QueryRow("SELECT user_id,expires_at from sessions where sessions.session_id = ?", session_id.Value).Scan(&user_id, &expires_at)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if expires_at.Before(now) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Valid session. Now get user info

	var id int
	var email string
	var subscription_id *int
	err = a.db.QueryRow("SELECT id, email, subscription_id FROM users WHERE users.id=?", user_id).Scan(&id, &email, &subscription_id)

	if err != nil {
		http.Error(w, "Failed to query user data", http.StatusInternalServerError)
		log.Printf("DB query error: %v", err)
		return
	}

	user := User{
		ID:             id,
		Email:          email,
		SubscriptionID: subscription_id,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func main() {
	templates = template.Must(template.ParseGlob("templates/*.html"))

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	dsn := "root:@tcp(localhost:3306)/platform?multiStatements=true&parseTime=true"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	defer db.Close()

	a := &app{db: db}

	if err := runMigrations(db); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	fmt.Println("Migrations applied successfully!")

	http.HandleFunc("/signup", a.signupHandler)
	http.HandleFunc("/login", a.loginHandler)

	http.HandleFunc("/", a.homePageHandler)
	fmt.Println("Server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func (a *app) signupHandler(w http.ResponseWriter, r *http.Request) {
	session_id, err := r.Cookie("db_session_id")

	if err != nil || session_id.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	log.Println(session_id.Value)
	var user_id int
	var expires_at time.Time
	now := time.Now()

	err = a.db.QueryRow("SELECT user_id,expires_at from sessions where sessions.session_id = ?", session_id.Value).Scan(&user_id, &expires_at)
	if err != nil {
		return
	}
	if expires_at.Before(now) {
		_, err = a.db.Exec("DELETE from sessions where sessions.id=?", session_id.Value)
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}
	if r.Method == http.MethodGet {
		err := templates.ExecuteTemplate(w, "signup.html", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if r.Method == http.MethodPost {
		name := r.FormValue("name")
		email := r.FormValue("email")
		pass := r.FormValue("password")
		hashedPass, _ := HashPasswordDeterministic(pass, "dbms")

		res, err := a.db.Exec(
			"INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
			name, email, hashedPass,
		)
		if err != nil {
			http.Error(w, "Failed to save user", http.StatusInternalServerError)
			log.Printf("DB insert error: %v", err)
			return
		}

		user_id, err := res.LastInsertId()
		sid, err := newSessionID()
		if err != nil {
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}
		exp := time.Now().Add(7 * 24 * time.Hour)
		_, err = a.db.Exec("INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)", sid, user_id, exp, time.Now())
		if err != nil {
			http.Error(w, "failed to persist session", http.StatusInternalServerError)
			log.Println(err)
			return

		}
		http.SetCookie(w, &http.Cookie{
			Name:     "db_session_id",
			Value:    sid,
			Path:     "/",
			Expires:  exp,
			MaxAge:   int(time.Until(exp).Seconds()),
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   false,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)

		log.Printf("User signed up: name=%s email=%s", name, email)
		return
	}

	templates.ExecuteTemplate(w, "signup", nil)
}

func (a *app) loginHandler(w http.ResponseWriter, r *http.Request) {

	session_id, err := r.Cookie("db_session_id")

	if err != nil || session_id.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	log.Println(session_id.Value)
	var user_id int
	var expires_at time.Time
	now := time.Now()

	err = a.db.QueryRow("SELECT user_id,expires_at from sessions where sessions.session_id = ?", session_id.Value).Scan(&user_id, &expires_at)
	if err != nil {
		return
	}
	if expires_at.Before(now) {
		_, err = a.db.Exec("DELETE from sessions where sessions.id=?", session_id.Value)
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}

	if r.Method == http.MethodGet {
		err := templates.ExecuteTemplate(w, "login.html", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if r.Method == http.MethodPost {
		var id int
		var username, passwordHash string
		email := r.FormValue("email")
		pass := r.FormValue("password")
		log.Printf("Login: email=%s pass=%s", email, pass)
		err := a.db.QueryRow("SELECT id, name, password_hash FROM users WHERE email = ?", email).Scan(&id, &username, &passwordHash)
		if err != nil {
			log.Fatal(err)
		}

		err = CheckPasswordDeterministic(pass, "dbms", []byte(passwordHash))

		if err != nil {
			http.Error(w, "Error", http.StatusInternalServerError)
			log.Printf("No user Found %v", err)
			return
		} else {
			log.Printf("success")
			// create a session and save the id in cookie and send a set req
			sid, err := newSessionID()
			if err != nil {
				http.Error(w, "failed to create session", http.StatusInternalServerError)
				return
			}
			exp := time.Now().Add(7 * 24 * time.Hour)
			_, err = a.db.Exec("INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)", sid, id, exp, time.Now())
			if err != nil {
				http.Error(w, "failed to persist session", http.StatusInternalServerError)
				log.Println(err)
				return

			}
			http.SetCookie(w, &http.Cookie{
				Name:     "db_session_id",
				Value:    sid,
				Path:     "/",
				Expires:  exp,
				MaxAge:   int(time.Until(exp).Seconds()),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Secure:   false,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	templates.ExecuteTemplate(w, "login", nil)
}
