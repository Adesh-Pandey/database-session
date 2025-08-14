package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"golang.org/x/crypto/bcrypt"
)

type app struct {
	db *sql.DB
}

var templates *template.Template

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

func (a *app) helloHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query("SELECT id, email, subscription_id FROM users")

	if err != nil {
		http.Error(w, "Failed to query users", http.StatusInternalServerError)
		log.Printf("DB query error: %v", err)
		return
	}

	defer rows.Close()

	var users []User

	for rows.Next() {
		var u User
		err := rows.Scan(&u.ID, &u.Email, &u.SubscriptionID)
		if err != nil {
			http.Error(w, "Failed to scan user", http.StatusInternalServerError)
			log.Printf("DB scan error: %v", err)
			return
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Error iterating rows", http.StatusInternalServerError)
		log.Printf("Rows error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func main() {
	templates = template.Must(template.ParseGlob("templates/*.html"))

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	dsn := "root:@tcp(127.0.0.1:3306)/platform?multiStatements=true"
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

	http.HandleFunc("/", a.helloHandler)
	fmt.Println("Server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func (a *app) signupHandler(w http.ResponseWriter, r *http.Request) {
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
		hashedPass, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)

		// Store into DB
		_, err := a.db.Exec(
			"INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
			name, email, hashedPass,
		)
		if err != nil {
			http.Error(w, "Failed to save user", http.StatusInternalServerError)
			log.Printf("DB insert error: %v", err)
			return
		}

		log.Printf("User signed up: name=%s email=%s", name, email)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	templates.ExecuteTemplate(w, "signup", nil)
}

func (a *app) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		err := templates.ExecuteTemplate(w, "login.html", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		pass := r.FormValue("password")
		log.Printf("Login: email=%s pass=%s", email, pass)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	templates.ExecuteTemplate(w, "login", nil)
}
