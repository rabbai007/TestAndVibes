const axios = require('axios');
const http = require('http');
const ALLOW = ['api.internal.example.com'];
function proxy(req) {
  // ruleid: vibecheck-ssrf-user-url-fetched
  fetch(req.query.url);
  // ruleid: vibecheck-ssrf-user-url-fetched
  axios.get(req.body.target);
  // ok: vibecheck-ssrf-user-url-fetched
  if (ALLOW.includes(req.query.url)) { fetch(req.query.url); }
  // ok: vibecheck-ssrf-user-url-fetched
  http.get('https://api.internal.example.com/health');
}
