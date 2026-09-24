require "net/http"
def proxy
  # ruleid: vibecheck-ssrf-user-url-fetched-rb
  Net::HTTP.get(URI(params[:url]))
  # ok: vibecheck-ssrf-user-url-fetched-rb
  Net::HTTP.get(URI("https://api.internal.example.com/health"))
end
