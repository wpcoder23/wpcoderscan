# WPCoderScan rules

This document describes every rule: what it reports, what vulnerable code looks like, what correct code looks like, and how confident the detection is. A Polish version is in [reguly.md](reguly.md).

**Confidence.** A *firm* finding is structurally unambiguous and fails the build by default. A *heuristic* finding can be a false alarm, so it only warns. The `--strict` flag counts heuristics toward the exit code too.

**Data flow.** The rules follow user input within a single function. A superglobal directly at the point of use gives a firm finding. A variable fed from a superglobal gives a heuristic. Other sources (the REST request object, shortcode attributes, `add_query_arg`) always give a medium-severity heuristic. A numeric cast, `absint`, `intval`, `esc_sql`, `$wpdb->prepare`, `escapeshellarg` and `basename` remove the taint. A variable checked before use against an allowlist (`in_array`, `array_key_exists`, `isset` on an array keyed by a variable, `ctype_*`, an anchored regex, a comparison with a literal) stops being tainted. Unknown functions do not carry taint, so the scanner prefers to miss something over burying you in false alarms.

| Rule | Severity | Confidence | CWE | Fix suggestion |
| --- | --- | --- | --- | --- |
| `wp.sqli.unprepared` | critical, high | firm or heuristic | CWE-89 | no |
| `wp.xss.echo_superglobal` | high, medium | heuristic | CWE-79 | yes |
| `wp.unserialize.user_input` | high | firm | CWE-502 | yes |
| `wp.rce.dynamic` | critical, high, medium | firm or heuristic | CWE-94 | no |
| `wp.rest.no_permission_callback` | high, medium | firm or heuristic | CWE-862 | no |
| `wp.auth.unprotected_action` | high | heuristic | CWE-352, CWE-862 | no |
| `wp.option.no_sanitize_callback` | medium | firm | CWE-20 | no |
| `wp.secret.hardcoded` | critical, high, medium | firm or heuristic | CWE-798 | no |
| `wp.sqli.param_unprepared` (`--extended` mode) | medium | heuristic | CWE-89 | no |

## wp.sqli.unprepared

A `$wpdb` query built from user input without `prepare`. A superglobal directly in the query is a firm, critical finding. A variable fed from a superglobal is a heuristic with high severity. Plain variables and table names are not reported.

```php
// Vulnerable
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders WHERE id = " . $_GET['id'] );

// Correct
$wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}orders WHERE id = %d", $_GET['id'] ) );
```

## wp.xss.echo_superglobal

User input in `echo`, `print`, `printf`, `die`, `wp_die` or in the value returned by a shortcode, without an escaping function. `json_encode` responses in `die`, `wp_die` and `printf` are skipped, because they are usually AJAX.

The source can be a superglobal, `filter_input`, `add_query_arg` without a URL, or shortcode attributes. Shortcode attributes (`$atts`, the keys from `shortcode_atts` and `extract`) are written by the post author, so the result is stored XSS, not reflected. This is a heuristic, because the scanner does not know all of a project's own sanitizing functions. For this rule the scanner provides a ready fix matched to the place in the HTML. See "Fix suggestions" in the README.

```php
// Vulnerable
<h2>Results for: <?php echo $_GET['q']; ?></h2>
<input value="<?php echo $_GET['q']; ?>">
<a href="<?php echo $_GET['back']; ?>">Back</a>

// Correct
<h2>Results for: <?php echo esc_html( $_GET['q'] ); ?></h2>
<input value="<?php echo esc_attr( $_GET['q'] ); ?>">
<a href="<?php echo esc_url( $_GET['back'] ); ?>">Back</a>
```

## wp.unserialize.user_input

`unserialize` or `maybe_unserialize` on superglobal data. It lets an attacker inject a PHP object and run a gadget chain from another plugin. A call that has the second argument `array( 'allowed_classes' => false )` is not reported. A class list instead of `false` lowers the report to a medium heuristic, because the risk remains if one of the classes has magic methods. The scanner suggests this fix for a single-argument `unserialize`.

```php
// Vulnerable
$settings = unserialize( $_POST['settings'] );

// Correct
$settings = json_decode( wp_unslash( $_POST['settings'] ), true );
// or, when you have to stay with serialization
$settings = unserialize( $_POST['settings'], array( 'allowed_classes' => false ) );
```

## wp.rce.dynamic

Code or command execution from user input: `eval`, `include` and `require` with a path from the user, backticks, and the `exec`, `system`, `shell_exec`, `passthru` family. Data straight from a superglobal is firm and critical. Data through a variable is a heuristic. `eval` without user input is a medium heuristic.

```php
// Vulnerable
include $_GET['template'] . '.php';

// Correct
$allowed = array( 'list', 'single' );
$name    = in_array( $_GET['template'], $allowed, true ) ? $_GET['template'] : 'list';
include __DIR__ . '/templates/' . $name . '.php';
```

## wp.rest.no_permission_callback

A REST route without `permission_callback`. A missing argument is a firm finding. `__return_true` on a route that changes data is a heuristic. Read-only routes (`GET`, `READABLE`) with `__return_true` are skipped, because that is a common and intentional pattern.

```php
// Vulnerable
register_rest_route( 'demo/v1', '/orders', array(
	'methods'  => 'POST',
	'callback' => 'demo_save_order',
) );

// Correct
register_rest_route( 'demo/v1', '/orders', array(
	'methods'             => 'POST',
	'callback'            => 'demo_save_order',
	'permission_callback' => function () {
		return current_user_can( 'manage_options' );
	},
) );
```

## wp.sqli.param_unprepared

An extended rule, enabled with the `--extended` flag. It reports a function parameter concatenated into a `$wpdb` query without `prepare`. The scanner cannot see the callers, so it does not know whether user input reaches the parameter. That is why it is always a medium-severity heuristic. Findings that the regular `wp.sqli.unprepared` rule already covers are skipped.

```php
// Vulnerable, if user input reaches the function
function demo_get_order( $id ) {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}orders WHERE id = " . $id );
}

// Correct
function demo_get_order( $id ) {
	global $wpdb;
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}orders WHERE id = %d", $id ) );
}
```

## wp.auth.unprotected_action

An `admin_post_*` or `wp_ajax_*` handler that changes state (saves an option, meta or database row, deletes something) without a nonce check and without a capability check. The handler can be a function, a closure or a class method from the same file (`[ $this, 'm' ]`, `[ self::class, 'm' ]`, `[ ClassName::class, 'm' ]`, `'ClassName::m'`). A missing capability check with a nonce present is medium severity, because the attack needs a logged-in account. A missing nonce, or both checks missing, is high severity. The rule skips handlers that call a helper with a guard-like name (containing, for example, `nonce`, `verify`, `permission`, `capability`). This is a heuristic.

```php
// Vulnerable
add_action( 'wp_ajax_demo_delete', function () {
	delete_option( 'demo_data' );
	wp_send_json_success();
} );

// Correct
add_action( 'wp_ajax_demo_delete', function () {
	check_ajax_referer( 'demo_delete' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( null, 403 );
	}
	delete_option( 'demo_data' );
	wp_send_json_success();
} );
```

## wp.option.no_sanitize_callback

`register_setting` without `sanitize_callback`. The option value is saved without validation.

```php
// Vulnerable
register_setting( 'demo_group', 'demo_option' );

// Correct
register_setting( 'demo_group', 'demo_option', array( 'sanitize_callback' => 'sanitize_text_field' ) );
```

## wp.secret.hardcoded

Hardcoded secrets in code. Provider keys with a known format (AWS, Stripe live, GitHub, Slack, SendGrid, a private key with its body) are firm findings. A Google API key is a high-severity heuristic, because browser maps keys are often public by design while paid API keys share the same format. Detection by variable name (`password`, `secret`, `api_key` and similar) is a heuristic and needs a value that looks like a secret: at least 12 characters, letters and digits, no spaces, not a URL, not a placeholder.

```php
// Vulnerable
$api_key = 'value-of-a-real-key';

// Correct
$api_key = defined( 'DEMO_API_KEY' ) ? DEMO_API_KEY : '';   // a constant in wp-config.php kept outside the repository
```

If a key has reached the repository, treat it as exposed and revoke it. Removing it from the code is not enough, because the key stays in the history.
