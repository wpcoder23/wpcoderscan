// Katalog komunikatów po angielsku. To język domyślny i źródło kluczy.
// Wartości mogą zawierać zmienne w klamrach, np. {method}. Polski katalog
// (pl.ts) musi mieć te same klucze i te same zmienne, pilnuje tego typ i test.
export const en = {
  // Tytuły reguł (raport SARIF).
  'rule.wp.sqli.unprepared.title': 'Database query without $wpdb->prepare built from user input',
  'rule.wp.sqli.param_unprepared.title': 'Function parameter concatenated into a $wpdb query without prepare',
  'rule.wp.rest.no_permission_callback.title': 'REST API route without access control',
  'rule.wp.rce.dynamic.title': 'Dynamic code or system command execution',
  'rule.wp.unserialize.user_input.title': 'unserialize on user input',
  'rule.wp.option.no_sanitize_callback.title': 'register_setting without sanitize_callback',
  'rule.wp.secret.hardcoded.title': 'Hardcoded secret in code',
  'rule.wp.xss.echo_superglobal.title': 'User input in echo or print without escaping',
  'rule.wp.auth.unprotected_action.title': 'Action handler without nonce or capability check',

  // Pochodzenie danych, wstawiane do komunikatów po słowie "data" lub "holds data".
  'origin.request': 'from a REST request',
  'origin.url': 'from the current page URL (add_query_arg without a URL)',
  'origin.param': 'from a function parameter',
  'origin.shortcode': 'from shortcode attributes',
  'origin.user': 'from user input',

  // SQL injection.
  'sqli.fix':
    'Use $wpdb->prepare() with %s, %d and %f placeholders and pass the data as arguments instead of concatenating it into the query string.',
  'sqli.direct': '$wpdb->{method}() inserts user input into the query without prepare. Risk of SQL injection.',
  'sqli.viaVar':
    '$wpdb->{method}() builds the query without prepare from variable {var}, which holds data {origin}. Probable SQL injection.',
  'sqli.param.message':
    '$wpdb->{method}() builds the query without prepare from the function parameter {var}. If user input reaches this function, it risks SQL injection.',
  'sqli.param.fix':
    'Use $wpdb->prepare() with placeholders and cast numbers with int or absint. Check column names and sort direction against an allowlist.',

  // XSS.
  'xss.fix':
    'Wrap the data in an escaping function that matches the context: esc_html in content, esc_attr in an attribute, esc_url in a URL. For HTML with tags use wp_kses_post.',
  'xss.direct': 'Data {origin} reaches {sink} without an escaping function. Risk of {kind}.',
  'xss.viaVar': 'Variable {var} holds data {origin} and reaches {sink} without an escaping function. Possible {kind}.',
  'xss.risk.stored': 'stored XSS',
  'xss.risk.reflected': 'reflected XSS',
  'xss.possible.stored': 'stored XSS',
  'xss.possible.reflected': 'reflected XSS',
  'xss.sink.echo': 'echo or print',
  'xss.sink.exit': 'die or exit',
  'xss.sink.shortcode': 'the HTML returned by a shortcode',
  'xss.sink.printf': 'printf',
  'xss.sink.wp_die': 'wp_die',
  'xss.patch.complete': 'Wrap the data in {names}.',
  'xss.patch.manual':
    'Wrap the data in {names}. The HTML context cannot be read from the code, so check that this is the right function.',
  'join.and': ' and ',

  // Wykonanie kodu i poleceń.
  'rce.from.direct': 'user input',
  'rce.from.viaVar': 'variable {var}, which holds data {origin}',
  'rce.eval.message': 'eval runs dynamically built code. This is a direct route to remote code execution.',
  'rce.eval.fix': 'Remove eval. Build the logic directly in PHP instead of executing text as code.',
  'rce.include.message':
    'include or require with a path built from {from}. Risk of including a foreign file and executing code.',
  'rce.include.fix':
    'Do not build the path from input data. Use a fixed allowlist of files, or paths relative to the plugin directory.',
  'rce.backtick.message': 'Backtick shell command built from {from}. Risk of operating system command injection.',
  'rce.shell.message': '{name}() runs a command built from {from}. Risk of operating system command injection.',
  'rce.shell.fix':
    'Avoid the shell. If you must use it, pass arguments through escapeshellarg and do not concatenate them into the command string.',

  // Deserializacja.
  'unserialize.full': '{name}() on superglobal data. Risk of PHP object injection.',
  'unserialize.limited':
    '{name}() on superglobal data with a restricted class list. Check that none of those classes has magic methods that can be abused.',
  'unserialize.fix':
    'Do not deserialize user input. Use json_decode with JSON data, or if you must, enforce allowed_classes => false.',
  'unserialize.patch': 'Block object creation: add allowed_classes => false.',

  // Opcje.
  'registerSetting.message': 'register_setting without sanitize_callback. The option value is saved without validation.',
  'registerSetting.fix':
    'Add sanitize_callback to the register_setting arguments array, for example sanitize_text_field or custom validation that fits the option type.',

  // Trasy REST.
  'rest.missing.message':
    'register_rest_route without permission_callback. The REST endpoint is reachable without a permission check.',
  'rest.missing.fix':
    'Add permission_callback and check permissions, for example with current_user_can or nonce verification. For an intentionally public endpoint, set it deliberately.',
  'rest.openWrite.message':
    'permission_callback set to __return_true on a route that changes data. The REST endpoint is open to everyone.',
  'rest.openWrite.fix':
    'If the endpoint is meant to be public, keep it deliberately. Otherwise check permissions with current_user_can or nonce verification.',

  // Sekrety.
  'secret.label.aws': 'AWS access key',
  'secret.label.stripe': 'Stripe live key',
  'secret.label.github': 'GitHub token',
  'secret.label.google': 'Google API key',
  'secret.label.slack': 'Slack token',
  'secret.label.privateKey': 'private key',
  'secret.label.sendgrid': 'SendGrid API key',
  'secret.note.google':
    'A browser maps key can be public by design, but paid API keys have the same format. Check in the Google console whether the key has restrictions.',
  'secret.provider': 'Hardcoded {label} detected in code.',
  'secret.byName': 'The value assigned to "{name}" looks like a hardcoded secret.',
  'secret.fix':
    'Move the secret out of the code, into an environment variable or into wp-config.php kept outside the repository. If it has reached the repository, rotate it.',

  // Nonce i uprawnienia.
  'auth.nonce.message': 'The handler for hook "{hook}" does not verify a nonce. Risk of CSRF.',
  'auth.nonce.fix':
    'Add check_admin_referer or check_ajax_referer at the start of the handler, and a wp_nonce_field in the form.',
  'auth.capability.message':
    'The handler for hook "{hook}" does not check user capabilities. Risk of unauthorized actions.',
  'auth.capability.fix':
    'Add current_user_can with the right capability at the start of the handler and stop when the user lacks it.',

  // Silnik i kolektor.
  'error.tooDeep': 'file nested too deeply, skipped',
  'error.parse': 'parse error: {detail}',
  'error.rule': 'rule {rule}: {detail}',
  'error.read': 'could not read file: {detail}',
  'git.notRepo': 'the directory is not a git repository, --diff mode needs git',
  'git.diffFailed': 'git diff failed for reference "{ref}"',

  // Raport w terminalu.
  'severity.critical': 'CRITICAL',
  'severity.high': 'HIGH',
  'severity.medium': 'MEDIUM',
  'severity.low': 'LOW',
  'severity.info': 'INFO',
  'report.title': 'WPCoderScan  scan: {target}',
  'report.counts': 'files: {files}, findings: {findings}',
  'report.heuristic': 'heuristic',
  'report.fix': 'fix: {text}',
  'report.suggestion': 'suggestion: {label}',
  'report.suggestion.manual': 'suggestion (needs a decision): {label}',
  'report.score': 'Score: {value}/100',
  'report.count.critical': 'critical {n}',
  'report.count.high': 'high {n}',
  'report.count.medium': 'medium {n}',
  'report.count.low': 'low {n}',
  'report.errors': 'scanner errors: {count}',
  'report.patchHint': 'fix suggestions: {count} (show them with --suggest)',

  // CLI.
  'cli.help': `WPCoderScan - security scanner for WordPress and PHP code

Usage:
  wpcoderscan <path> [options]

Options:
  --json              print the result as JSON
  --sarif             print the result as SARIF 2.1.0 (for the GitHub Security tab)
  --fail-on <level>   exit with code 1 when a finding of this level or higher exists
                      (critical, high, medium, low, none; default high)
  --strict            count heuristic findings toward the exit code too
                      (by default only firm findings fail the build)
  --diff <ref>        scan only PHP files changed against a git ref
                      (default HEAD; fast scan for pull requests)
  --extended          include extended rules (higher sensitivity, more false alarms)
  --suggest           show fix suggestions next to findings (writes nothing)
  --patch <file>      write complete fix suggestions as a patch for git apply
  --lang <en|pl>      output language (default en; also env WPCODERSCAN_LANG)
  -v, --version       show the version
  -h, --help          this help
`,
  'cli.error': 'error: {message}',
  'cli.patch.none': 'No complete fix suggestions, so no patch was created.',
  'cli.patch.saved': 'Patch saved to {file}: {patches} fixes in {files} files.',
  'cli.patch.apply': 'Review it and apply it: git apply --check {file} && git apply {file}',
  'cli.patch.manual': 'Skipped {count} suggestions that need a decision. See them with --suggest.',
  'cli.badFailOn': 'unknown --fail-on level "{value}", use critical, high, medium, low or none',
} as const;

export type MessageKey = keyof typeof en;
