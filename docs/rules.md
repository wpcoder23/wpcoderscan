# WPCoderScan rules

This document describes every rule: what it reports, what vulnerable code looks like, what correct code looks like, and how confident the detection is. A Polish version is in [reguly.md](reguly.md).

**Confidence.** A *firm* finding is structurally unambiguous and fails the build by default. A *heuristic* finding can be a false alarm, so it only warns. The `--strict` flag counts heuristics toward the exit code too.

**Data flow.** The rules follow user input inside a function and across calls between functions of the same file. A superglobal directly at the point of use gives a firm finding. A variable fed from a superglobal gives a heuristic. Other sources (the REST request object, shortcode attributes, `add_query_arg`) always give a medium-severity heuristic. When a function of the file is called with user input as an argument, that parameter counts as user input inside the function. This works for functions and for `$this->method()`, `self::`, `static::` and `ClassName::` calls, through chains of up to six calls. Calls into other files are not followed. A function that passes its first parameter to `shortcode_atts` counts as a shortcode handler, even when `add_shortcode` is in another file.

A numeric cast, `absint`, `intval`, `escapeshellarg` and `basename` remove the taint. So does `$wpdb->prepare`, for the values passed as arguments. `esc_sql`, `addslashes` and `$wpdb->_escape` remove it only for a value inside quotes in the query.

A variable checked before use against an allowlist stops being tainted. The checks that count are `in_array`, `array_key_exists`, `isset` on an array keyed by a variable, `ctype_*`, `is_numeric`, an anchored regex, a regex that rejects any character outside a set, a comparison with a literal, and a call to a validator named like `is_valid_*`, `is_allowed_*` or `validate_*`. A check counts inside the `if` body, in the branches of a ternary and after an early exit.

A default written into an element of a superglobal does not clear it. `$_REQUEST['orderby'] = 'id'` inside an `if ( empty( $_REQUEST['orderby'] ) )` branch leaves the visitor's value in the other branch, so the rest of the function still sees `$_REQUEST['orderby']` as user input. A write that reads the superglobal itself and cleans it (`$_GET['x'] = sanitize_text_field( $_GET['x'] )`, `(int) $_GET['x']`) still clears it.

**Branches.** A write inside the body of an `if`, a `switch` case, a loop or a `catch` is not certain to run. Cleaning a variable there does not clean it for the code after the construct, unless the condition tests that very variable (`if ( ! empty( $name ) ) { $name = esc_html( $name ); }`). A write in one branch is not visible in a sibling branch. A later full write in the same branch replaces the earlier writes of that branch. Taint assigned inside a branch reaches the code after it. The scanner does not follow conditions through the code, so a flag that picks the branch is not understood.

Functions that return a piece or a copy of their argument carry taint: text functions such as `strtr`, `strstr`, `str_pad` and `wordwrap`, array functions such as `array_shift`, `array_column` and `current`, and path and address builders such as `dirname`, `trailingslashit`, `admin_url` and `home_url`. The address builders carry it only into XSS findings. The host of such an address is your own site, so they do not carry it into SSRF findings. Other unknown functions do not carry taint, so the scanner prefers to miss something over burying you in false alarms.

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
| `wp.file.path_traversal` (`--extended` mode) | critical, high, medium, low | firm or heuristic | CWE-22, CWE-73 | no |
| `wp.http.ssrf` (`--extended` mode) | high, medium, low | firm or heuristic | CWE-918 | no |
| `wp.upload.unrestricted` (`--extended` mode) | critical, high, medium, low | firm or heuristic | CWE-434 | no |
| `wp.privilege.escalation` (`--extended` mode) | critical, high | firm or heuristic | CWE-269 | no |
| `wp.option.arbitrary_update` (`--extended` mode) | critical, high, medium, low | firm or heuristic | CWE-915 | no |

## Administrator gate

The five extended rules look at who can reach the code. Code that only an administrator can reach is not an open door for a visitor. The path, address and upload rules lower such a finding to a low-severity hint. The account and option rules skip it. The scanner reads these as a gate:

- `current_user_can( 'manage_options' )` and other administrator capabilities (`manage_*`, `install_plugins`, `edit_users`, `promote_users` and similar), also when the capability sits in a variable that only ever holds such a value,
- `is_super_admin()`, a role check for `administrator` and `$user->has_cap( 'manage_options' )`,
- a call to a function or method named after an administrator check (`user_is_admin`, `check_admin_permission`, `can_manage_options`), or to a wrapper such as `$this->check_permission( 'manage_options' )` that receives an administrator capability,
- a menu page registered with such a capability, and a REST route whose `permission_callback` checks it or is named after an administrator check. The callback of the page or route is behind the gate,
- a hook registered inside an `if` that checks an administrator capability, or after an early exit for everyone else (`if ( ! current_user_can( 'manage_options' ) ) { return; }`). `is_admin()` alone does not count, because it asks about the admin screen and not about the user. A function that is also registered without such a check is open,
- a helper that the same file calls only from code behind the gate. A handler calls a helper, and the helper calls another helper. A function that is also registered as a hook callback, or called on an object of an unknown class, does not count.

A nonce is not a gate, because every visitor gets one. `check_admin_referer()` checks a nonce, so it is not a gate either. A capability for an ordinary user (`edit_posts`) is not a gate. The scanner does not judge whether the check is correct, and it does not see a gate that sits in another file.

## Suppressing findings

A reviewed finding can be silenced in three ways, from narrow to wide.

- An ignore comment next to the code: `// wpcoderscan-ignore wp.rce.dynamic -- reason`. The rule id is required. `wpcoderscan-ignore-file` covers the whole file.
- A baseline file, which hides the findings that already existed when the gate was introduced.
- The `rules` and `exclude` options in `.wpcoderscan.json`, which switch off a rule or skip paths for the whole project.

The README describes each of them in [Adopt it in an existing codebase](../README.md#adopt-it-in-an-existing-codebase).

## wp.sqli.unprepared

A `$wpdb` query built from user input without `prepare`. A superglobal directly in the query is a firm, critical finding. A variable fed from a superglobal is a heuristic with high severity. Plain variables and table names are not reported.

`prepare` protects only the values passed as arguments. User input pasted into the query text that `prepare` receives is still reported (`ORDER BY $orderby`, a column name, a table name built from input).

`esc_sql`, `addslashes` and `$wpdb->_escape` protect only text inside quotes. A value escaped this way but placed outside quotes is reported with high severity. That covers a number after `=`, a column name, `LIMIT`, `ORDER BY` and text between backticks. The finding is firm when the superglobal sits right in the expression. It is a heuristic when the data comes through a variable.

The rule also reads the SQL that WordPress assembles for you. A function registered on `posts_where`, `posts_orderby`, `posts_join` and the related hooks (`posts_search`, `posts_groupby`, `posts_fields`, `posts_clauses`, `posts_request`, `terms_clauses`, `comments_clauses`) returns text that WordPress pastes into the query. User input in that value is reported. So is user input assigned to `query_where`, `query_orderby` and the other `query_*` properties of a query object (`pre_user_query`). The quoting rules above apply: `esc_sql` protects a value inside quotes and does not protect one outside them.

```php
// Vulnerable
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders WHERE id = " . $_GET['id'] );
add_filter( 'posts_orderby', function () { return $_GET['order']; } );
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders ORDER BY " . esc_sql( $_GET['orderby'] ) );

// Correct
$wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}orders WHERE id = %d", $_GET['id'] ) );
$orderby = in_array( $_GET['orderby'], array( 'date', 'total' ), true ) ? $_GET['orderby'] : 'date';
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders ORDER BY $orderby" );
```

## wp.xss.echo_superglobal

User input in `echo`, `print`, `printf`, `die`, `wp_die` or in the value returned by a shortcode, without an escaping function. `json_encode` responses in `die`, `wp_die` and `printf` are skipped, because they are usually AJAX.

The source can be a superglobal, `filter_input`, `add_query_arg` without a URL, or shortcode attributes. Shortcode attributes (`$atts`, the keys from `shortcode_atts` and `extract`) are written by the post author, so the result is stored XSS, not reflected. This is a heuristic, because the scanner does not know all of a project's own sanitizing functions. For this rule the scanner provides a ready fix matched to the place in the HTML. See "Fix suggestions" in the README.

The rule also reports user input that lands in HTML which the code assembles and does not print itself. Three shapes count. A function returns a string with HTML tags built from user data. A variable collects such HTML (`$html .= '<li>' . $_GET['x']`) and the function returns it. A property stores it (`$this->content = '<div>' . $_GET['x'] . '</div>'`). The code that prints the result is often in another file, so these findings have medium severity. User data pasted into `do_shortcode()` is reported for the same reason, because a visitor can then add a shortcode or an attribute of their own.

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

`unserialize` or `maybe_unserialize` on superglobal data, or on a variable fed from user input (a heuristic). A call inside `if ( is_serialized_string( $x ) )` is skipped, because such a string cannot hold an object. It lets an attacker inject a PHP object and run a gadget chain from another plugin. A call that has the second argument `array( 'allowed_classes' => false )` is not reported. A class list instead of `false` lowers the report to a medium heuristic, because the risk remains if one of the classes has magic methods. The scanner suggests this fix for a single-argument `unserialize`.

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

Template loaders are sinks as well: `get_template_part`, `locate_template`, `load_template`, `wc_get_template`, `wc_get_template_part` and `wc_get_template_html`, and methods whose names say they load a template (`get_template`, `load_template`, `render_template`, `include_template` and similar). A template name built from user input can contain `../` and pull in a PHP file from outside the template folder. A loader defined in the same file is not reported at the call. The `include` inside it is reported once a caller passes user input.

```php
// Vulnerable
include $_GET['template'] . '.php';
get_template_part( 'parts/' . $_GET['part'] );

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

An extended rule, enabled with the `--extended` flag. It reports a function parameter concatenated into a `$wpdb` query without `prepare`, when nothing in the file passes user input to that parameter. The scanner cannot see the callers in other files, so it does not know whether user input reaches the parameter. That is why it is always a medium-severity heuristic. When a call from the same file passes user input, the regular `wp.sqli.unprepared` rule reports it instead. Findings that the regular rule already covers are skipped.

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

## wp.file.path_traversal

An extended rule, enabled with the `--extended` flag. A file is read, written or deleted at a path that comes from user input. An attacker can read `wp-config.php`, overwrite a file with PHP code or delete a file and take the site over.

The rule covers `file_get_contents`, `readfile`, `file`, `fopen`, `parse_ini_file`, `simplexml_load_file`, `highlight_file`, `copy`, `rename`, `file_put_contents`, `unlink`, `wp_delete_file` and the `$wp_filesystem` methods `get_contents`, `put_contents`, `copy`, `move` and `delete`. A path taken straight from a superglobal is a firm finding. A variable fed from user input is a heuristic. A write is critical when firm and high as a heuristic. A read or a delete is high when firm and medium as a heuristic.

The rule does not report a path reduced with `basename`, `wp_basename` or `sanitize_file_name`. It skips a path that the function checks (`validate_file`, `realpath`, a search for `..`) and a URL with a fixed host, because the SSRF rule covers URLs. It skips a path where user data stands only in the file name after a fixed fragment (`'img-' . $id`). It skips a read or a delete of a file with a fixed harmless extension (`.jpg`, `.json`, `.csv`, `.txt`). A write to such a path is a low-severity heuristic, because the file cannot run as code. A function behind an administrator capability check is a low-severity heuristic too.

```php
// Vulnerable
echo file_get_contents( WP_CONTENT_DIR . '/uploads/' . $_GET['file'] );
unlink( $_POST['path'] );

// Correct
$name = wp_basename( $_GET['file'] );
$base = realpath( WP_CONTENT_DIR . '/uploads' );
$path = realpath( $base . '/' . $name );
if ( $path && str_starts_with( $path, $base . DIRECTORY_SEPARATOR ) ) {
	echo file_get_contents( $path );
}
```

## wp.http.ssrf

An extended rule, enabled with the `--extended` flag. The server sends an HTTP request to an address that comes from user input. An attacker can make the server call internal services, cloud metadata addresses or other hosts.

The rule covers `wp_remote_get`, `wp_remote_post`, `wp_remote_request`, `wp_remote_head`, `wp_remote_fopen`, `get_headers`, `curl_init`, the `CURLOPT_URL` option of `curl_setopt` and `curl_setopt_array`, `fsockopen`, `pfsockopen` and `stream_socket_client`. The start of the address decides the result, because it holds the scheme and the host. User data appended after a fixed host (`'https://api.example.com/?q=' . $q`) only changes the query, so it is not reported. A host fixed in a variable counts as fixed. The `wp_safe_remote_*` functions reject internal addresses, so they are outside the rule. So is an address that the function checks with `wp_http_validate_url`, `parse_url` or `wp_parse_url`. A firm finding is high. A heuristic is medium. A function behind an administrator capability check is a low-severity heuristic.

```php
// Vulnerable
$response = wp_remote_get( $_GET['url'] );

// Correct
$response = wp_safe_remote_get( esc_url_raw( $_GET['url'] ) );
$response = wp_remote_get( 'https://api.example.com/v1/items?q=' . rawurlencode( $_GET['q'] ) );
```

## wp.upload.unrestricted

An extended rule, enabled with the `--extended` flag. An uploaded file is saved under a name that comes from the client, and nothing in the function checks the file type. An attacker can upload a PHP script and run code.

Two forms. The first is `move_uploaded_file` with a target path built from user input. The second is `wp_handle_upload` or `wp_handle_sideload` with `'test_type' => false`, which turns off the core type check. A name taken straight from `$_FILES` is a firm finding. A file of unknown origin, for example a function parameter, is a medium heuristic. A function behind an administrator capability check is a low-severity heuristic.

A check counts when it stands before the save. That means a call to `wp_check_filetype`, `wp_check_filetype_and_ext`, `getimagesize`, `exif_imagetype`, `mime_content_type` or `finfo_*`. It also means reading the extension with `pathinfo` and comparing it with a list, comparing the client's `type` field with a list, checking the ending of the name (`str_ends_with( $name, '.json' )`) or calling a function whose name says that it validates the file type (`is_allowed_file_type`, `validate_upload`). A check after the save counts only when the function deletes the file that fails it. A fixed target extension that cannot run (`.jpg`, `.json`) ends the report. A fixed `.php` does not, because the client chooses the content.

```php
// Vulnerable
move_uploaded_file( $_FILES['file']['tmp_name'], WP_CONTENT_DIR . '/uploads/' . $_FILES['file']['name'] );

// Correct
$check = wp_check_filetype( $_FILES['file']['name'], array( 'jpg|jpeg' => 'image/jpeg', 'png' => 'image/png' ) );
if ( $check['ext'] ) {
	move_uploaded_file( $_FILES['file']['tmp_name'], WP_CONTENT_DIR . '/uploads/' . sanitize_file_name( $_FILES['file']['name'] ) );
}
```

## wp.privilege.escalation

An extended rule, enabled with the `--extended` flag. The role, the login or the capabilities of an account are controlled by the request. An attacker can create an administrator account or sign in as any user.

Four forms. A role from the request reaches `wp_insert_user`, `wp_update_user`, `set_role`, `add_role` or `add_cap`, or the whole request is passed as account data (`wp_insert_user( $_POST )`). A user meta key from the request reaches `update_user_meta` or `add_user_meta`, so the request can write `wp_capabilities`. A value from the request is written to the capabilities meta. A user ID from the request reaches `wp_set_auth_cookie` or `wp_set_current_user` and nothing in the function proves who the visitor is.

Proof of identity is a call to `wp_check_password`, `wp_signon`, `hash_equals`, `password_verify`, `hash_hmac`, `openssl_verify`, a request to a login provider, a capability check, or a function named like `verify_*`, `authenticate_*` or `decode_jwt`. A nonce is no proof, because every visitor gets one. A function behind an administrator capability is not reported. That includes a menu page or a REST route that is registered with such a capability. A login in a function that checks for a development environment is skipped, because it does not run in production.

```php
// Vulnerable
wp_insert_user( array( 'user_login' => $_POST['login'], 'user_pass' => $_POST['pass'], 'role' => $_POST['role'] ) );
wp_set_auth_cookie( (int) $_GET['user_id'] );

// Correct
wp_insert_user( array( 'user_login' => sanitize_user( $_POST['login'] ), 'user_pass' => $_POST['pass'], 'role' => 'subscriber' ) );
```

## wp.option.arbitrary_update

An extended rule, enabled with the `--extended` flag. The name of a WordPress option comes from user input. An attacker can change `default_role` or `users_can_register` and take the site over, or delete a core option and break it.

The rule covers `update_option`, `add_option`, `delete_option` and their site and network variants. A fixed prefix in the name (`'demo_' . $key`) limits the scope to the plugin's own options, so it is not reported. A fixed ending of five or more characters (`$_POST['addon'] . '_notice_ignore'`) lowers the result to a low-severity heuristic. Endings that name role options (`user_roles`, `capabilities`) are the exception. A fixed value (`update_option( $name, true )`) lowers the result by one level, because the attacker picks the name but not the value. A check of the prefix before the write is a guard when the prefix has at least four characters: `strpos( $key, 'demo_' ) !== 0` followed by an exit, or `str_starts_with( $key, 'demo_' )` in the condition. The loose comparison `!= 0` is not a guard, because `false == 0`. A function behind an administrator capability check is not reported. That includes a menu page or a REST route that is registered with such a capability.

```php
// Vulnerable
update_option( $_POST['name'], $_POST['value'] );

// Correct
$allowed = array( 'demo_color', 'demo_size' );
if ( in_array( $_POST['name'], $allowed, true ) ) {
	update_option( $_POST['name'], sanitize_text_field( $_POST['value'] ) );
}
```

## wp.auth.unprotected_action

An `admin_post_*` or `wp_ajax_*` handler, including the `nopriv` variants, that changes state (saves an option, meta or database row, deletes something) without a nonce check and without a capability check. The handler can be a function, a closure or a class method from the same file (`[ $this, 'm' ]`, `[ self::class, 'm' ]`, `[ ClassName::class, 'm' ]`, `'ClassName::m'`). A missing capability check with a nonce present is medium severity, because the attack needs a logged-in account. A missing nonce, or both checks missing, is high severity. The finding points at the handler definition, not at the `add_action` call. This is a heuristic.

The rule follows calls to functions and methods from the same file. It looks for a nonce or capability check up to three calls deep. It counts a state change in a helper only up to two calls deep, and only when the helper gets request data in an argument or reads `$_GET`, `$_POST`, `$_REQUEST` or `$_FILES` itself. A helper that only tidies the plugin's own data says nothing about who controls the handler.

The rule skips three kinds of handlers.

- Handlers that call a helper with a guard-like name, for example one containing `nonce`, `verify`, `permission`, `capability`, `can_`, `is_user_logged_in` or `validate_ajax`. The scanner reads snake_case and camelCase alike, so `isUserAllowedToEdit()` counts like `is_user_allowed_to_edit()`. Names that only sound similar do not count, for example `wp_get_current_user`, `get_access_token` or `wp_kses_allowed_html`.
- Handlers that write only to the profile of the logged-in user, such as `update_user_meta( get_current_user_id(), ... )`, or `update_user_option( $user->ID, ... )` after `$user = wp_get_current_user()`. They change only the caller's own data.
- Handlers named like the dismissal of a notice, banner, tooltip or tour (for example `dismiss`, `notice`, `banner`, `pointer`, `welcome`, `promo`, `remind`) that only store an option, transient or user meta under a key that does not come from the request. They save interface state, not site data.

The rule does not ask for a capability check in a handler that the same file registers for both `wp_ajax_*` and `wp_ajax_nopriv_*` with the same callback. Such a handler is public by design, so only the nonce check counts. The exception ends when the handler changes something that an ordinary public form does not change: a site option, another account or its password, a role or capability, a plugin or theme, existing content or a file. A handler like that stays open to anonymous users through the `nopriv` hook, so the capability finding stays.

The `init` and `admin_init` hooks are not checked. A test on popular plugins gave noise there and no additional vulnerability.

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
