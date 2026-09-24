package main
import "net/http"
func proxy(r *http.Request) {
	// ruleid: vibecheck-ssrf-user-url-fetched-go
	http.Get(r.URL.Query().Get("url"))
	// ok: vibecheck-ssrf-user-url-fetched-go
	http.Get("https://api.internal.example.com/health")
}
