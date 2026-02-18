package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
)

var templates *template.Template

func main() {

	// ----- PORT RENDER -----
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// ----- LOAD TEMPLATES -----
	var err error
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal("Erreur chargement templates:", err)
	}

	mux := http.NewServeMux()

	// ----- ROUTES -----

	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/register", registerHandler)

	// ----- STATIC FILES (si besoin) -----
	// mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("🚀 Server started on port", port)

	err = http.ListenAndServe(":"+port, mux)
	if err != nil {
		log.Fatal(err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		http.Error(w, "Erreur template index", http.StatusInternalServerError)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		err := templates.ExecuteTemplate(w, "login.html", nil)
		if err != nil {
			http.Error(w, "Erreur template login", http.StatusInternalServerError)
		}
		return
	}

	// POST (simulation simple)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		err := templates.ExecuteTemplate(w, "register.html", nil)
		if err != nil {
			http.Error(w, "Erreur template register", http.StatusInternalServerError)
		}
		return
	}

	// POST (simulation simple)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
