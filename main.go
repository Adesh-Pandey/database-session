package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

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

// Temporary signup data stored in memory during the signup process
type TempSignupData struct {
	Name     string
	Email    string
	Password string
}

// In-memory store for temporary signup data (use Redis in production)
var tempSignupStore = make(map[string]TempSignupData)

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

type UserCard struct {
	ID      int
	Name    string
	Age     int
	Bio     string
	Gender  string
	ImgPath string
}

type TinderPageData struct {
	CurrentUser UserCard
	Users       []UserCard
}

type SwipeRequest struct {
	SwipedID int  `json:"swiped_id"`
	IsLike   bool `json:"is_like"`
}

type MatchCard struct {
	ID       int
	Name     string
	Age      int
	Bio      string
	Gender   string
	ImgPath  string
	InstaURL string
}

type MatchesPageData struct {
	CurrentUser UserCard
	Matches     []MatchCard
}

func HashPasswordDeterministic(password, secret string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password+secret), bcrypt.DefaultCost)
}

func CheckPasswordDeterministic(password, secret string, hashed []byte) error {
	return bcrypt.CompareHashAndPassword(hashed, []byte(password+secret))
}

func (a *app) matchesHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("db_session_id")
	if err != nil || sessionID.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Get current user ID
	var currentUserID int
	err = a.db.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionID.Value).Scan(&currentUserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Get current user info
	var currentUser UserCard
	err = a.db.QueryRow("SELECT id, name, age, bio, gender, img_path FROM users WHERE id = ?", currentUserID).
		Scan(&currentUser.ID, &currentUser.Name, &currentUser.Age, &currentUser.Bio, &currentUser.Gender, &currentUser.ImgPath)
	if err != nil {
		http.Error(w, "Failed to load user", http.StatusInternalServerError)
		return
	}

	// Get matches
	rows, err := a.db.Query(`
        SELECT u.id, u.name, u.age, u.bio, u.gender, u.img_path, u.insta_url
        FROM matches m
        JOIN users u ON (u.id = m.matched_user_id)
        WHERE m.user_id = ?`, currentUserID)
	if err != nil {
		http.Error(w, "Failed to load matches", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var matches []MatchCard
	for rows.Next() {
		var m MatchCard
		if err := rows.Scan(&m.ID, &m.Name, &m.Age, &m.Bio, &m.Gender, &m.ImgPath, &m.InstaURL); err != nil {
			log.Println(err)
			continue
		}
		matches = append(matches, m)
	}

	data := MatchesPageData{
		CurrentUser: currentUser,
		Matches:     matches,
	}

	err = templates.ExecuteTemplate(w, "matches.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) swipeHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID, err := r.Cookie("db_session_id")
	if err != nil || sessionID.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// 1. Get current user ID
	var currentUserID int
	err = a.db.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionID.Value).Scan(&currentUserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var req SwipeRequest
	decode_err := json.NewDecoder(r.Body).Decode(&req)
	if decode_err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err = a.db.Exec(
		"INSERT INTO swipes (swiper_id, swiped_id, is_like) VALUES (?, ?, ?)",
		currentUserID, req.SwipedID, req.IsLike,
	)

	if err != nil {
		http.Error(w, "Failed to save swipe", http.StatusInternalServerError)
		return
	}

	if req.IsLike {
		var count int
		err = a.db.QueryRow(
			"SELECT COUNT(*) FROM swipes WHERE swiper_id = ? AND swiped_id = ? AND is_like = true",
			req.SwipedID, currentUserID,
		).Scan(&count)
		if err == nil && count > 0 {
			// Create a match
			_, err = a.db.Exec(
				"INSERT IGNORE INTO matches (user_id, matched_user_id) VALUES (?, ?), (?, ?)",
				currentUserID, req.SwipedID, req.SwipedID, currentUserID,
			)
			if err != nil {
				log.Println("Failed to insert match:", err)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

}
func (a *app) homePageHandler(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("db_session_id")
	if err != nil || sessionID.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// 1. Get current user ID
	var currentUserID int
	err = a.db.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionID.Value).Scan(&currentUserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// 2. Get current user info
	var currentUser UserCard
	err = a.db.QueryRow("SELECT id, name, age, bio, gender, img_path FROM users WHERE id = ?", currentUserID).
		Scan(&currentUser.ID, &currentUser.Name, &currentUser.Age, &currentUser.Bio, &currentUser.Gender, &currentUser.ImgPath)
	if err != nil {
		http.Error(w, "Failed to load user", http.StatusInternalServerError)
		return
	}

	// 3. Get all other users who are not already swiped by current user
	rows, err := a.db.Query(`
        SELECT id, name, age, bio, gender, img_path 
        FROM users 
        WHERE id != ? AND id NOT IN (
            SELECT swiped_id FROM swipes WHERE swiper_id = ?
        )`, currentUserID, currentUserID)
	if err != nil {
		http.Error(w, "Failed to load other users", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []UserCard
	for rows.Next() {
		var u UserCard
		if err := rows.Scan(&u.ID, &u.Name, &u.Age, &u.Bio, &u.Gender, &u.ImgPath); err != nil {
			log.Println(err)
			continue
		}
		users = append(users, u)
	}

	// 4. Pass data to template
	data := TinderPageData{
		CurrentUser: currentUser,
		Users:       users,
	}

	err = templates.ExecuteTemplate(w, "home.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Step 1: Basic signup (name, email, password)
func (a *app) signupStep1Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		err := templates.ExecuteTemplate(w, "signup-step1.html", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		name := r.FormValue("name")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if name == "" || email == "" || password == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}

		// Check if email already exists
		var existingID int
		err := a.db.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&existingID)
		if err == nil {
			http.Error(w, "Email already registered", http.StatusConflict)
			return
		}

		// Generate temporary token for step 2
		tempToken, err := newSessionID()
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Store temporary data
		tempSignupStore[tempToken] = TempSignupData{
			Name:     name,
			Email:    email,
			Password: password,
		}

		// Set temporary cookie and redirect to step 2
		http.SetCookie(w, &http.Cookie{
			Name:     "signup_token",
			Value:    tempToken,
			Path:     "/",
			MaxAge:   1800, // 30 minutes
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   false,
		})

		http.Redirect(w, r, "/signup/step2", http.StatusSeeOther)
		return
	}
}

// Step 2: Profile setup (bio, image, age, gender)
func (a *app) signupStep2Handler(w http.ResponseWriter, r *http.Request) {
	// Get temporary signup data
	tokenCookie, err := r.Cookie("signup_token")
	if err != nil || tokenCookie.Value == "" {
		http.Redirect(w, r, "/signup", http.StatusFound)
		return
	}

	tempData, exists := tempSignupStore[tokenCookie.Value]
	if !exists {
		http.Redirect(w, r, "/signup", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		data := map[string]string{
			"Name":  tempData.Name,
			"Email": tempData.Email,
		}
		err := templates.ExecuteTemplate(w, "signup-step2.html", data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		// Parse multipart form for file upload
		err := r.ParseMultipartForm(10 << 20) // 10 MB max
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		bio := r.FormValue("bio")
		ageStr := r.FormValue("age")
		gender := r.FormValue("gender")
		insta_url := r.FormValue("insta_url")

		age, err := strconv.Atoi(ageStr)
		if err != nil {
			http.Error(w, "Invalid age", http.StatusBadRequest)
			return
		}

		// Handle file upload
		var profileImagePath string
		file, header, err := r.FormFile("img_path")
		if err == nil {
			defer file.Close()

			// Create uploads directory if it doesn't exist
			uploadsDir := "static/uploads"
			os.MkdirAll(uploadsDir, 0755)

			// Generate unique filename
			ext := filepath.Ext(header.Filename)
			filename := fmt.Sprintf("%d_%s%s", time.Now().Unix(), tempData.Email, ext)
			profileImagePath = fmt.Sprintf("/static/uploads/%s", filename)

			// Save file
			dst, err := os.Create(filepath.Join(uploadsDir, filename))
			if err != nil {
				http.Error(w, "Failed to save image", http.StatusInternalServerError)
				return
			}
			defer dst.Close()

			_, err = io.Copy(dst, file)
			if err != nil {
				http.Error(w, "Failed to save image", http.StatusInternalServerError)
				return
			}
		}

		// Now create the user with all data
		hashedPass, err := HashPasswordDeterministic(tempData.Password, "dbms")
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}

		res, err := a.db.Exec(
			"INSERT INTO users (name, email, password_hash, bio, img_path, age, gender, insta_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			tempData.Name, tempData.Email, hashedPass, bio, profileImagePath, age, gender, insta_url,
		)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			log.Printf("DB insert error: %v", err)
			return
		}

		userID, err := res.LastInsertId()
		if err != nil {
			http.Error(w, "Failed to get user ID", http.StatusInternalServerError)
			return
		}

		// Create session
		sid, err := newSessionID()
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		exp := time.Now().Add(7 * 24 * time.Hour)
		_, err = a.db.Exec("INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
			sid, userID, exp, time.Now())
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			log.Println(err)
			return
		}

		// Clean up temporary data
		delete(tempSignupStore, tokenCookie.Value)

		// Clear signup token and set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "signup_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})

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
		log.Printf("User signup completed: name=%s email=%s", tempData.Name, tempData.Email)
		return
	}
}

func (a *app) loginHandler(w http.ResponseWriter, r *http.Request) {
	// Check for existing session
	session_id, err := r.Cookie("db_session_id")
	if err == nil && session_id.Value != "" {
		var user_id int
		var expires_at time.Time
		now := time.Now()

		err = a.db.QueryRow("SELECT user_id,expires_at from sessions where sessions.session_id = ?", session_id.Value).Scan(&user_id, &expires_at)
		if err == nil && expires_at.After(now) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
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

		err := a.db.QueryRow("SELECT id, name, password_hash FROM users WHERE email = ?", email).Scan(&id, &username, &passwordHash)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		err = CheckPasswordDeterministic(pass, "dbms", []byte(passwordHash))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Create session
		sid, err := newSessionID()
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		exp := time.Now().Add(7 * 24 * time.Hour)
		_, err = a.db.Exec("INSERT INTO sessions (session_id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
			sid, id, exp, time.Now())
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
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
		return
	}
}

func main() {
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Serve static files and uploads
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

	// Route handlers
	http.HandleFunc("/signup", a.signupStep1Handler)
	http.HandleFunc("/signup/step2", a.signupStep2Handler)
	http.HandleFunc("/login", a.loginHandler)
	http.HandleFunc("/", a.homePageHandler)
	http.HandleFunc("/swipe", a.swipeHandler)
	http.HandleFunc("/matches", a.matchesHandler)

	fmt.Println("Server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
