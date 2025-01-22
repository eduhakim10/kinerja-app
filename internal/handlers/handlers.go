package handlers

import (
    "encoding/json"
    "net/http"
    "github.com/julienschmidt/httprouter"
    "kinerja-app/internal/models"
    "github.com/jmoiron/sqlx"
	  "golang.org/x/crypto/bcrypt"
	     "log"
	"html/template"
)

var db *sqlx.DB

// Set DB
func SetDB(database *sqlx.DB) {
    db = database
}


// GetUsers - Handler untuk mendapatkan daftar pengguna
func GetUsers(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    var users []models.User
    err := db.Select(&users, "SELECT * FROM users")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(users)
}
func DeleteUser (w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    id := ps.ByName("id")
    _, err := db.Exec("DELETE FROM users WHERE id = ?", id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}
func UpdateUser (w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    var user models.User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    id := ps.ByName("id")
    _, err := db.Exec("UPDATE users SET username = ?, password = ?, role = ? WHERE id = ?", user.Username, user.Password, user.Role, id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

func CreateReport(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    var report models.Report

    // Decode JSON request body ke dalam struct Report
    if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Pastikan TaskID dan Achievements diisi
    if report.TaskID == 0 || report.Achievements == 0 {
        http.Error(w, "TaskID and Achievements are required", http.StatusBadRequest)
        return
    }

    // Eksekusi query untuk memasukkan laporan ke dalam database
    _, err := db.Exec("INSERT INTO reports (task_id, achievements, notes, file_path, status) VALUES (?, ?, ?, ?, ?)", 
        report.TaskID, report.Achievements, report.Notes, report.FilePath, "Menunggu Verifikasi") // Status default
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Mengatur status response
    w.WriteHeader(http.StatusCreated)
}

// GetReports - Handler untuk mendapatkan daftar laporan
func GetReports(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    var reports []models.Report
    err := db.Select(&reports, "SELECT * FROM reports")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(reports)
}
func ServeIndex(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    // Mendapatkan cookie username
    cookie, err := r.Cookie("username")
    if err != nil {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    username := cookie.Value

    // Ambil ID pengguna berdasarkan username
    var user models.User
    err = db.Get(&user, "SELECT * FROM users WHERE username = ?", username)
    
    var tasks []models.Task

    if err != nil {
        log.Println("User  not found, fetching all tasks")
        err = db.Select(&tasks, `
            SELECT t.*, 
                   u1.name AS reporter_name, 
                   u2.name AS verifier_name, 
                   r.status 
            FROM tasks t 
            LEFT JOIN users u1 ON t.reporter_id = u1.id 
            LEFT JOIN users u2 ON t.verifier_id = u2.id 
            LEFT JOIN reports r ON t.id = r.task_id
        `)
		if err != nil {
            log.Println("Unable to fetch tasks:", err)
            // Tetap tampilkan halaman meskipun tidak ada tugas
        }

    } else {
        // Ambil daftar tugas berdasarkan ID pengguna (reporter_id atau verifier_id)
        err = db.Select(&tasks, `
            SELECT t.*, 
                   u1.name AS reporter_name, 
                   u2.name AS verifier_name, 
                   r.status 
            FROM tasks t 
            LEFT JOIN users u1 ON t.reporter_id = u1.id 
            LEFT JOIN users u2 ON t.verifier_id = u2.id 
            LEFT JOIN reports r ON t.id = r.task_id 
            WHERE t.reporter_id = ? OR t.verifier_id = ?
        `, user.ID, user.ID)
		if err != nil {
            log.Println("Unable to fetch tasks:", err)
            // Tetap tampilkan halaman meskipun tidak ada tugas
        }

    }

    // Render template dengan data
    tmpl, err := template.ParseFiles("frontend/templates/index.html")
    if err != nil {
        http.Error(w, "Unable to load template", http.StatusInternalServerError)
        return
    }

    data := struct {
        Username string
        Tasks    []models.Task
    }{
        Username: username,
        Tasks:    tasks,
    }

    if err := tmpl.Execute(w, data); err != nil {
        http.Error(w, "Unable to execute template", http.StatusInternalServerError)
    }
}



func ServeLogin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    http.ServeFile(w, r, "frontend/templates/login.html")
}
func ServeTask(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    // Ambil username dari cookie
    cookie, err := r.Cookie("username")
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    username := cookie.Value

    // Ambil semua tugas dari database
    var tasks []models.Task
    err = db.Select(&tasks, "SELECT * FROM tasks")
    if err != nil {
        http.Error(w, "Unable to fetch tasks", http.StatusInternalServerError)
        return
    }

    // Render template dengan data tugas dan username
    tmpl, err := template.ParseFiles("frontend/templates/task.html")
    if err != nil {
        http.Error(w, "Unable to load template", http.StatusInternalServerError)
        return
    }

    // Kirim data ke template
    data := struct {
        Tasks   []models.Task
        Username string
    }{
        Tasks:   tasks,
        Username: username,
    }

    // Eksekusi template dengan data
    if err := tmpl.Execute(w, data); err != nil {
        http.Error(w, "Unable to execute template", http.StatusInternalServerError)
    }
}

func ServeUser (w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    // Ambil semua pengguna dari database
    var users []models.User
    err := db.Select(&users, "SELECT * FROM users")
    if err != nil {
        http.Error(w, "Unable to fetch users", http.StatusInternalServerError)
        return
    }

    // Render template dengan data pengguna
    tmpl, err := template.ParseFiles("frontend/templates/user.html")
    if err != nil {
        http.Error(w, "Unable to load template", http.StatusInternalServerError)
        return
    }

    // Kirim data ke template
    data := struct {
        Users []models.User
    }{
        Users: users,
    }

    // Eksekusi template dengan data
    if err := tmpl.Execute(w, data); err != nil {
        http.Error(w, "Unable to execute template", http.StatusInternalServerError)
    }
}


// Login - Handler untuk memproses login
// Login - Handler untuk memproses login
func Login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    var credentials struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }

    log.Println("Received login request")

    if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
        log.Println("Error decoding request body:", err)
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    log.Printf("Attempting to login user: %s", credentials.Username)

    var user models.User
    err := db.Get(&user, "SELECT * FROM users WHERE username = ?", credentials.Username)
    if err != nil {
        log.Println("Invalid credentials:", err)
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
    if err != nil {
        log.Println("Password verification failed for user:", credentials.Username)
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Set cookie untuk menyimpan informasi pengguna
    http.SetCookie(w, &http.Cookie{
        Name:  "username",
        Value: user.Username,
        Path:  "/",
        // Anda bisa menambahkan atribut lain seperti MaxAge, HttpOnly, Secure, dll.
    })

    log.Printf("Login successful, redirecting to home page")
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Logout - Handler untuk logout
func Logout(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    // Hapus header atau session yang menyimpan informasi pengguna
    w.Header().Del("X-User ") // Hapus header X-User 
    http.Redirect(w, r, "/login", http.StatusSeeOther) // Redirect ke halaman login
}

// CreateUser  - Handler untuk membuat pengguna baru
func CreateUser (w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    var user models.User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Failed to hash password", http.StatusInternalServerError)
        return
    }
    user.Password = string(hashedPassword)

    // Simpan pengguna ke database
    _, err = db.Exec("INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)",user.Name, user.Username, user.Password, user.Role)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusCreated)
}

func CreateTask(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    var task models.Task

    // Decode JSON request body ke dalam struct Task
    if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Validasi input
    if task.Title == "" || task.Deadline == "" || task.ReporterID == 0 || task.VerifierID == 0 {
        http.Error(w, "Title, Deadline, ReporterID, and VerifierID are required", http.StatusBadRequest)
        return
    }

    // Simpan task ke database
    _, err := db.Exec("INSERT INTO tasks (title, deadline, reporter_id, verifier_id) VALUES (?, ?, ?, ?)", 
        task.Title, task.Deadline, task.ReporterID, task.VerifierID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Mengatur status response
    w.WriteHeader(http.StatusCreated)
}

func UpdateTask(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    var task models.Task

    // Decode JSON request body ke dalam struct Task
    if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Ambil ID dari parameter URL
    id := ps.ByName("id")

    // Validasi input
    if task.Title == "" || task.Deadline == "" || task.ReporterID == 0 || task.VerifierID == 0 {
        http.Error(w, "Title, Deadline, ReporterID, and VerifierID are required", http.StatusBadRequest)
        return
    }

    // Update task di database
    _, err := db.Exec("UPDATE tasks SET title = ?, deadline = ?, reporter_id = ?, verifier_id = ? WHERE id = ?", 
        task.Title, task.Deadline, task.ReporterID, task.VerifierID, id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Mengatur status response
    w.WriteHeader(http.StatusNoContent) // 204 No Content
}
func UpdateReport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    var report models.Report

    // Decode JSON request body ke dalam struct Report
    if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Ambil ID dari parameter URL
    id := ps.ByName("id")

    // Validasi input
    if report.TaskID == 0 || report.Achievements == 0 || report.Status == "" {
        http.Error(w, "TaskID, Achievements, and Status are required", http.StatusBadRequest)
        return
    }

    // Update report di database
    _, err := db.Exec("UPDATE reports SET task_id = ?, achievements = ?, notes = ?, file_path = ?, status = ? WHERE id = ?", 
        report.TaskID, report.Achievements, report.Notes, report.FilePath, report.Status, id)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Mengatur status response
    w.WriteHeader(http.StatusNoContent) // 204 No Content
}

