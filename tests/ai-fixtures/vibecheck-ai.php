<?php
// ruleid: vibecheck-untrusted-input-in-system-prompt-php
$m = ['role' => 'system', 'content' => $_GET['persona']];
function ex($client) {
  $resp = $client->chat()->create([]);
  // ruleid: vibecheck-llm-output-executed-php
  system($resp->content);
}
function htmlout($client) {
  $r = $client->chat()->create([]);
  // ruleid: vibecheck-llm-output-raw-html-php
  echo $r->content;
}
