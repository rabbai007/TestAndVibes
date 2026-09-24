function search(req) {
  // ruleid: vibecheck-user-controlled-regex
  const re = new RegExp(req.query.pattern);
  // ok: vibecheck-user-controlled-regex
  const safe = new RegExp('^[a-z0-9]+$');
  return re.test('x') || safe.test('y');
}
