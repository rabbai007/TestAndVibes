<?php
// ruleid: vibecheck-ssrf-user-url-fetched-php
$data = file_get_contents($_GET['url']);
// ok: vibecheck-ssrf-user-url-fetched-php
$ok = file_get_contents("https://api.internal.example.com/health");
