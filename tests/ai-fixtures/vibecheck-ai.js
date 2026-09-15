const cp = require('child_process');
const anthropic = require('@anthropic-ai/sdk');
function h(req) {
  // ruleid: vibecheck-untrusted-input-in-system-prompt
  anthropic.messages.create({ system: `You are ${req.body.persona}`, messages: [] });
  // ok: vibecheck-untrusted-input-in-system-prompt
  anthropic.messages.create({ system: `static prompt`, messages: [{ role: 'user', content: req.body.q }] });
}
async function ex() {
  const r = await anthropic.messages.create({ messages: [] });
  // ruleid: vibecheck-llm-output-executed
  cp.exec(r.content[0].text);
}
async function html(el) {
  const r = await anthropic.messages.create({ messages: [] });
  // ruleid: vibecheck-llm-output-raw-html
  el.innerHTML = r.content[0].text;
}
const http = require('http');
