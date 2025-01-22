package main

import (
    "log"
    "net/http"
    "github.com/julienschmidt/httprouter"
    "github.com/jmoiron/sqlx"
	 "kinerja-app/internal/middleware"
    _ "github.com/go-sql-driver/mysql"
    "kinerja-app/internal/handlers"
	 "github.com/casbin/casbin/v2"
)
var enforcer *casbin.Enforcer

func main() {

	var err error
    enforcer, err = casbin.NewEnforcer("internal/models/rbac_model.conf", "config/policy.csv")
    if err != nil {
        log.Fatalf("Failed to initialize Casbin: %v", err)
    }
    // Koneksi ke database
    db, err := sqlx.Connect("mysql", "username:password@tcp(localhost:3306)/kinerja_db")
    if err != nil {
        log.Fatalln(err)
    }
    defer db.Close()

    // Set DB di handlers
    handlers.SetDB(db)

    // Router
    router := httprouter.New()
   // router.POST("/users", handlers.CreateUser ) gunakan ini menggunakan Postman untuk create user pertama

    //router.GET("/users", handlers.GetUsers)
    router.POST("/reports", handlers.CreateReport)
    router.GET("/reports", handlers.GetReports)

	router.POST("/users", middleware.AuthMiddleware(handlers.CreateUser))
	router.GET("/users", middleware.AuthMiddleware(handlers.ServeUser))
	router.PUT("/users/:id", middleware.AuthMiddleware(handlers.UpdateUser) )
	router.DELETE("/users/:id", middleware.AuthMiddleware(handlers.DeleteUser) )

	router.POST("/tasks", middleware.AuthMiddleware(handlers.CreateTask) )
	router.PUT("/tasks/:id", middleware.AuthMiddleware(handlers.UpdateTask))

	router.PUT("/reports/:id", middleware.AuthMiddleware(handlers.UpdateReport) ) // Rute untuk memperbarui laporan


	router.GET("/", middleware.AuthMiddleware(handlers.ServeIndex))
	router.GET("/tugas", middleware.AuthMiddleware(handlers.ServeTask))

	router.GET("/login", handlers.ServeLogin)
	router.POST("/login", handlers.Login)
	router.GET("/logout", handlers.Logout)



	// Rute untuk file statis
	router.ServeFiles("/static/*filepath", http.Dir("frontend/static"))


    // Jalankan server
    log.Println("Server berjalan di :8000")
    if err := http.ListenAndServe(":8000", router); err != nil {
        log.Fatalln(err)
    }
}