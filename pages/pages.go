package pages

import "embed"

// TemplateFiles contains the embedded HTML templates. Parse them with:
//
//	template.ParseFS(pages.TemplateFiles, "templates/*.html")
//
//go:embed templates
var TemplateFiles embed.FS

// StaticFiles contains the embedded static assets (CSS, etc.). Serve them with:
//
//	sub, _ := fs.Sub(pages.StaticFiles, "static")
//	http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
//
//go:embed static
var StaticFiles embed.FS
