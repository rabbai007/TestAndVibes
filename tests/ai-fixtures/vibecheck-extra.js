const http = require('http');
http.createServer((rq, rs) => {
  // ruleid: vibecheck-raw-http-reflected-request-data
  rs.end(`<h1>${rq.headers.host}</h1>`);
});
function bodyf(rq) {
  let buf = '';
  // ruleid: vibecheck-unbounded-request-body
  rq.on('data', (c) => { buf += c; });
}
// ruleid: vibecheck-unguarded-json-parse
const cfg = JSON.parse(process.env.CONFIG);
