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
  'rule.wp.file.path_traversal.title': 'File read, write or delete with a path from user input',
  'rule.wp.http.ssrf.title': 'HTTP request to an address from user input',
  'rule.wp.upload.unrestricted.title': 'File upload without a file type check',
  'rule.wp.privilege.escalation.title': 'Account role, login or capability controlled by the request',
  'rule.wp.option.arbitrary_update.title': 'Option name controlled by user input',

  // Pochodzenie danych, wstawiane do komunikatów po słowie "data" lub "holds data".
  'origin.request': 'from a REST request',
  'origin.url': 'from the current page URL (add_query_arg without a URL)',
  'origin.param': 'from a function parameter',
  'origin.shortcode': 'from shortcode attributes',
  'origin.caller': 'passed in by a caller in this file, originally from user input',
  'origin.user': 'from user input',

  // SQL injection.
  'sqli.fix':
    'Use $wpdb->prepare() with %s, %d and %f placeholders and pass the data as arguments instead of concatenating it into the query string.',
  'sqli.direct': '$wpdb->{method}() inserts user input into the query without prepare. Risk of SQL injection.',
  'sqli.viaVar':
    '$wpdb->{method}() builds the query without prepare from variable {var}, which holds data {origin}. Probable SQL injection.',
  'sqli.unquoted':
    '$wpdb->{method}() puts user input into the query outside quotes. esc_sql() and addslashes() protect only text inside quotes, so a number, column name or ORDER BY clause built this way can still be injected.',
  'sqli.unquoted.viaVar':
    '$wpdb->{method}() puts variable {var}, which holds data {origin}, into the query outside quotes. esc_sql() and addslashes() protect only text inside quotes, so a number, column name or ORDER BY clause built this way can still be injected.',
  'sqli.unquoted.fix':
    'Cast numbers with absint or (int). Check column names and sort direction against an allowlist. Escaping alone does not protect a value that stands outside quotes.',
  'sqli.clause.direct':
    'User input goes into the SQL clause {target} without prepare. WordPress adds this text to the query. Risk of SQL injection.',
  'sqli.clause.viaVar':
    'Variable {var}, which holds data {origin}, goes into the SQL clause {target} without prepare. WordPress adds this text to the query. Probable SQL injection.',
  'sqli.clause.unquoted':
    'User input goes into the SQL clause {target} outside quotes. esc_sql() and addslashes() protect only text inside quotes, so a number, column name or ORDER BY clause built this way can still be injected.',
  'sqli.clause.unquoted.viaVar':
    'Variable {var}, which holds data {origin}, goes into the SQL clause {target} outside quotes. esc_sql() and addslashes() protect only text inside quotes, so a number, column name or ORDER BY clause built this way can still be injected.',
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
  'xss.sink.html': 'HTML text that the code assembles',
  'xss.sink.do_shortcode': 'a do_shortcode call',
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
  'rce.template.message':
    '{name}() loads a template with a name built from {from}. A name with ../ can pull in a PHP file from outside the template folder.',
  'rce.template.fix':
    'Map the allowed template names to fixed files and reject anything else. Do not pass input straight into a template loader.',
  'rce.backtick.message': 'Backtick shell command built from {from}. Risk of operating system command injection.',
  'rce.shell.message': '{name}() runs a command built from {from}. Risk of operating system command injection.',
  'rce.shell.fix':
    'Avoid the shell. If you must use it, pass arguments through escapeshellarg and do not concatenate them into the command string.',

  // Reguły ujść: pliki, adresy HTTP, wysyłanie plików, role i opcje.
  'from.direct': 'user input',
  'from.viaVar': 'variable {var}, which holds data {origin}',
  'file.read.message':
    '{name}() reads a file from a path that comes from {from}. An attacker can read files such as wp-config.php.',
  'file.write.message':
    '{name}() writes a file to a path that comes from {from}. An attacker can overwrite files or plant PHP code.',
  'file.delete.message':
    '{name}() deletes a file at a path that comes from {from}. An attacker can delete files such as wp-config.php and take the site over.',
  'file.fix':
    'Do not build the path from input data. Map allowed names to fixed files, or reduce the input to a file name with wp_basename() and check that realpath() stays inside the expected folder.',
  'ssrf.message':
    '{name}() sends a request to an address that comes from {from}. An attacker can make the server call internal services or other hosts.',
  'ssrf.fix':
    'Do not take the address from input data. Use a fixed address, or check the host against an allowlist. wp_safe_remote_get() rejects internal addresses, and wp_http_validate_url() checks an address.',
  'upload.move.message':
    'move_uploaded_file() saves the file under a name that comes from {from}, and nothing in this function checks the file type. An attacker can upload a PHP script and run code.',
  'upload.notype.message':
    '{name}() runs with the file type check turned off (test_type is false). An attacker can upload a PHP script and run code.',
  'upload.fix':
    'Check the extension and type against an allowlist with wp_check_filetype_and_ext(), choose the file name yourself (wp_unique_filename()) and do not store uploads where the server runs PHP.',
  'privilege.role.message':
    'The account role is set to a value that comes from {from}. An attacker can give themselves the administrator role.',
  'privilege.setrole.message':
    '{name} sets a role to a value that comes from {from}. An attacker can give themselves the administrator role.',
  'privilege.userdata.message':
    '{name}() receives the whole request as account data, so the request can also set the role. An attacker can create an administrator account.',
  'privilege.meta.message':
    '{name}() writes user meta under a key that comes from {from}. An attacker can write the wp_capabilities key and become an administrator.',
  'privilege.caps.message':
    '{name}() writes the capabilities of an account with a value that comes from {from}. An attacker can grant themselves any permission.',
  'privilege.login.message':
    '{name}() signs in the account with an ID that comes from {from}. Nothing in this function proves who the visitor is. An attacker can sign in as any user, including an administrator.',
  'privilege.role.fix':
    'Do not take the role from the request. Set a fixed role (for example subscriber) and leave the choice of a role to users with the promote_users capability.',
  'privilege.meta.fix':
    'Use a fixed key or an allowlist of keys. Do not let the request choose a key that can be wp_capabilities or wp_user_level.',
  'privilege.login.fix':
    'Sign the account in only after you prove who the visitor is, for example with a password check, a one-time token compared with hash_equals(), or a signed link. Do not trust a user ID from the request.',
  'option.update.message':
    '{name}() changes an option whose name comes from {from}. An attacker can change settings such as default_role or users_can_register and take the site over.',
  'option.delete.message':
    '{name}() deletes an option whose name comes from {from}. An attacker can delete core options and break the site.',
  'option.fix':
    'Do not take the option name from input data. Use a fixed name, or check it against a list of your own options, and require a capability such as manage_options.',

  // Deserializacja.
  'unserialize.full': '{name}() on superglobal data. Risk of PHP object injection.',
  'unserialize.limited':
    '{name}() on superglobal data with a restricted class list. Check that none of those classes has magic methods that can be abused.',
  'unserialize.viaVar': '{name}() on variable {var}, which holds data {origin}. Possible PHP object injection.',
  'unserialize.viaVar.limited':
    '{name}() on variable {var}, which holds data {origin}, with a restricted class list. Check that none of those classes has magic methods that can be abused.',
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
  'report.suppressed': 'suppressed by comments: {count}',
  'report.baselined': 'in baseline: {count}',
  'report.warnings': 'warnings: {count}',
  'report.staleBaseline': 'baseline entries without a match: {count} (refresh the file with --write-baseline)',

  // Komentarze wyciszające, plik ustawień i baseline.
  'warn.ignoreNoRule': 'wpcoderscan-ignore needs a rule id, so the comment was ignored',
  'warn.ignoreUnknownRule': 'wpcoderscan-ignore: "{rule}" matches no rule',
  'config.notFound': 'config file not found: {file}',
  'config.invalid': 'cannot use config file {file}: {detail}',
  'config.expectedObject': 'the top level must be a JSON object',
  'config.unknownKey': '{file}: unknown option "{key}"',
  'config.badType': '{file}: option "{key}" has the wrong type, expected {expected}',
  'config.badRuleValue': '{file}: rule "{rule}" in "rules" can only be set to "off"',
  'config.unknownRule': '{file}: "rules" lists "{rule}", which is not a rule',
  'config.badLang': '{file}: unknown language "{value}" in "lang", supported languages: {supported}',
  'config.using': 'using config {file}',
  'baseline.notFound': 'baseline file not found: {file}',
  'baseline.invalid': 'the baseline file is not valid. Create it again with --write-baseline',
  'baseline.saved': 'Baseline saved to {file}: {count} findings. From now on only new findings are reported.',

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
  --baseline <file>   hide the findings listed in a baseline file, report only new ones
  --write-baseline <file>
                      save the current findings as a baseline and exit with code 0
  --config <file>     read settings from a file
                      (default: .wpcoderscan.json in the current directory)
  --no-config         do not read the settings file
  --no-ignore-comments
                      do not honor wpcoderscan-ignore comments in the scanned code
  --lang <en|pl>      output language (default en; also env WPCODERSCAN_LANG)
  -v, --version       show the version
  -h, --help          this help
`,
  'cli.error': 'error: {message}',
  'cli.patch.none': 'No complete fix suggestions, so no patch was created.',
  'cli.patch.saved': 'Patch saved to {file}: {patches} fixes in {files} files.',
  'cli.patch.apply': 'Review it and apply it: git apply --check {file} && git apply {file}',
  'cli.patch.manual': 'Skipped {count} suggestions that need a decision. See them with --suggest.',
  'cli.warning': 'warning: {message}',
  'cli.missingValue': 'option {option} needs a value',
  'cli.baselineDiff': '--write-baseline cannot be combined with --diff, because the baseline would cover only the changed files',
  'cli.badFailOn': 'unknown --fail-on level "{value}", use critical, high, medium, low or none',
} as const;

export type MessageKey = keyof typeof en;
