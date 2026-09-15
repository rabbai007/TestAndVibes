package main
import (
	"os/exec"
	"net/http"
)
func h(r *http.Request) {
	// ruleid: vibecheck-untrusted-input-in-system-prompt-go
	openai.SystemMessage(r.URL.Query().Get("persona"))
}
func ex(c *Client, ctx interface{}, params interface{}) {
	resp, _ := c.Messages.New(ctx, params)
	// ruleid: vibecheck-llm-output-executed-go
	exec.Command("sh", "-c", resp.Content)
}
