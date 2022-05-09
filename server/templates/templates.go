package templates

import (
	"html/template"
	"log"
	"net/http"
)

var (
	templates = template.Must(template.ParseFiles(
		"./server/templates/templatesFiles/login.gohtml",
		"./server/templates/templatesFiles/register.gohtml",
		"./server/templates/templatesFiles/restricted.gohtml"))
)

type LoginPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RegisterPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RestrictedPage struct {
	Csrf          string
	SecretMessage string
}

func RenderTemplate(w http.ResponseWriter, tmpl string, p interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".gohtml", p)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
