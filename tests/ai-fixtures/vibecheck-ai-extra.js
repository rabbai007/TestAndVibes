const anthropic = require('@anthropic-ai/sdk');
const openai = require('openai');
function prompts() {
  // ruleid: vibecheck-secret-in-llm-prompt
  anthropic.messages.create({ system: `The DB url is ${process.env.DATABASE_URL}`, messages: [] });
  // ok: vibecheck-secret-in-llm-prompt
  anthropic.messages.create({ system: `You are a helpful assistant`, messages: [] });
}
function calls(client) {
  // ruleid: vibecheck-llm-call-unbounded
  client.chat.completions.create({ model: 'gpt-4o', messages: [] });
  // ok: vibecheck-llm-call-unbounded
  client.chat.completions.create({ model: 'gpt-4o', messages: [], max_tokens: 500 });
}
