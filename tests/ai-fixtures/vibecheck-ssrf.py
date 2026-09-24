import requests
from flask import request
ALLOWED = {"api.internal.example.com"}
def proxy():
    u = request.args.get("url")
    # ruleid: vibecheck-ssrf-user-url-fetched-py
    requests.get(u)
    # ruleid: vibecheck-ssrf-user-url-fetched-py
    requests.post(request.json["callback"], json={})
    # ok: vibecheck-ssrf-user-url-fetched-py
    if u in ALLOWED:
        requests.get(u)
    # ok: vibecheck-ssrf-user-url-fetched-py
    requests.get("https://api.internal.example.com/health")
