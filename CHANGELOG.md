# Changelog

## 0.6.0

Five new rules in `--extended` mode, for bugs that the scanner did not look for before.

The new rules look at file paths, outgoing HTTP requests, uploads, accounts and options. They are off by default, like the other extended rules. The main set of 475 pairs of a CVE and a plugin version gives the same result as in 0.5.0: 144 (30.3%) in the default mode and 162 (34.1%) with `--extended`. A second set of 301 pairs covers the classes of the new rules. With `--extended` the scanner reports a finding of the right class within 25 lines of the CVE line in 58 of them (19.3%). Without the new rules the same scan reports 12 (4.0%). The rules were tuned while that set was visible, so it is not a blind test. On the popular plugins the default mode is unchanged. Of the 200 plugins, 198 still download. They give 579 findings, a median of 1 per plugin and 96 plugins without a finding. With `--extended` the new rules add 43 findings in 19 of those plugins, all of them heuristics. The scanner also ran over 252 plugins and themes from a local disk (42 151 PHP files) without a crash. There is no false-positive rate. See `benchmark/README.md` for the method and its limits.

- `wp.file.path_traversal` (CWE-22, and CWE-73 for writes). A file is read, written, copied or deleted at a path that comes from user input. It covers `file_get_contents`, `readfile`, `fopen`, `copy`, `rename`, `file_put_contents`, `unlink`, `wp_delete_file` and the `$wp_filesystem` methods. A path reduced with `basename`, a path that the function checks with `realpath` or `validate_file`, and a read or a delete of a file with a fixed harmless extension are not reported.
- `wp.http.ssrf` (CWE-918). An HTTP request goes to an address that comes from user input (`wp_remote_*`, `curl_init`, `CURLOPT_URL`, `fsockopen`). User data appended after a fixed host is not reported. `wp_safe_remote_*` is outside the rule.
- `wp.upload.unrestricted` (CWE-434). An uploaded file is saved under the client's name and nothing checks the file type, or `wp_handle_upload` runs with `test_type` turned off. A check before the save ends the report. So does a check after the save, when the function deletes the file that fails it.
- `wp.privilege.escalation` (CWE-269). The role, the user meta key or the user ID that reaches `wp_insert_user`, `update_user_meta`, `wp_set_auth_cookie` and similar functions comes from the request, and nothing proves who the visitor is.
- `wp.option.arbitrary_update` (CWE-915). The name of an option comes from user input (`update_option( $_POST['name'], ... )`). A fixed prefix, a check of the prefix before the write and a fixed ending lower the result or remove it.
- Administrator gate. Code that only an administrator can reach is not an open door for a visitor. The path, address and upload rules give such a finding a low severity, and the account and option rules stay quiet. The scanner reads as a gate an administrator capability check, a menu page or a REST route registered with one, a hook registered only under such a check or after an early exit, a permission function named like an administrator check, and a helper that the same file calls only from code behind a gate. A nonce is not a gate. `check_admin_referer()` is not a gate. A gate in another file is not seen. See `docs/rules.md`.
- The server sets `$_FILES['x']['tmp_name']`, `size` and `error`, so they no longer count as user input in any rule. The name and the type that the client sends still do.
- Firm findings of the new rules, such as an option name taken straight from a superglobal, fail the build under `--extended` at the default `--fail-on high`. Heuristics only warn.
- SARIF describes the new rules when the result contains them. Each new rule has a fix hint in English and in Polish.
- The benchmark has a second set, `data/cves-extra.json` (326 CVE entries in 284 plugin versions, 302 pairs, 301 of them still download), and a script, `recall-extra.mjs`, that counts the hits with and without the new rules. `run.mjs` runs it together with the other measurements.
- Known gap. CVE-2023-6827 (essential-real-estate 4.3.5) is missed, because the upload rule counts an extension check on zip entries after the save, followed by a delete, as validation.

Better recall on known vulnerabilities, with the same noise on popular plugins.

On 475 pairs of a CVE and a vulnerable plugin version (2023 to 2025), the default mode now reports a finding of the right class within 25 lines of the CVE line in 144 cases (30.3%), up from 117 (24.6%). With `--extended` it is 162 (34.1%), up from 139 (29.3%). On the 200 most popular plugins the total is unchanged at 580 findings, the median is still 1 per plugin, and 97 plugins have no finding. There is no false-positive rate. See `benchmark/README.md` for the method and its limits.

- Data flow follows calls between functions of the same file, up to six levels deep. It covers functions and `$this->method()`, `self::`, `static::` and `ClassName::` calls. A parameter that a caller fills with user input counts as user input inside the function. Array arguments with literal keys are followed element by element. Calls into other files are still not followed.
- A function that passes its first parameter to `shortcode_atts` counts as a shortcode handler, also when `add_shortcode` is in another file. A shortcode function that returns an array is not treated as output.
- `wp.sqli.unprepared`: `$wpdb->prepare` protects only the values passed as arguments. User input pasted into the query text it receives is now reported (`ORDER BY $orderby`, a column or table name).
- `wp.sqli.unprepared`: `esc_sql`, `addslashes` and `$wpdb->_escape` protect only text inside quotes. A value escaped this way but used outside quotes (a number, a column, `ORDER BY`, `LIMIT`, text between backticks) is reported with high severity. Before, any use of `esc_sql` counted as safe.
- `wp.unserialize.user_input` follows variables and reports them as a heuristic. A call inside `if ( is_serialized_string( $x ) )` is skipped.
- `wp.rce.dynamic` reports template loaders that receive user input: `get_template_part`, `locate_template`, `load_template`, `wc_get_template`, `wc_get_template_part`, `wc_get_template_html`, and methods such as `get_template` or `render_template` (CWE-98). A data array passed to the loader is not a template name and is ignored. A loader defined in the same file is followed instead of being reported at the call.
- `wp.sqli.param_unprepared` (`--extended`): when a call in the same file passes user input to the parameter, the regular `wp.sqli.unprepared` rule reports it and this rule stays quiet.
- More allowlist guards: `array_filter( $list, 'is_numeric' )`, a regular expression that rejects any character outside a set (`/[^a-z0-9_]/i`, `/\W/`), calls to validators named like `is_valid_*`, `is_allowed_*` and `validate_*`, and array elements with several literal keys (`$_POST['order'][0]['dir']`). A check also counts inside a ternary and on a single array element. Validators for e-mail, URL, date and tokens do not count, because they do not limit a value to a safe set.
- `wc_clean` clears XSS findings like `sanitize_text_field`, and does not clear SQL, path or command findings.
- `wp.auth.unprotected_action` reports at the handler definition, not at the `add_action` line, because that is where the check has to be added. Three authorization pairs of the benchmark (CVE-2025-5304, CVE-2025-13403, CVE-2025-14366) are no longer within 25 lines of their CVE line because of this.
- The `benchmark/` folder holds the scripts and data that produce the recall and noise numbers, so anyone can repeat them.

## 0.4.0

English by default.

- All output is in English by default: help, the terminal report, finding messages, fix hints, SARIF rule descriptions, JSON messages and errors. Polish stays available with `--lang pl` or `WPCODERSCAN_LANG=pl`. The flag wins over the variable. Locale names such as `pl_PL` and `en_US.UTF-8` are accepted. A bad `--lang` value is an error (exit code 2). A bad variable value only prints a warning and falls back to English.
- Library: `scan()` takes a `lang` option (default `en`) and `ScanResult` has a new `lang` field. Rules receive `lang` and `t()` in `FileContext`. The library never reads the environment, only the CLI does.
- Breaking for custom rules: `Rule.title` is replaced by `Rule.titleKey`, a key in the translation catalog (`src/i18n`). The package had not been published to npm before this release.
- The GitHub Action has a new input `lang` (default `en`). The action description and inputs are in English.
- `--fail-on` with an unknown level now fails with exit code 2. Before, a typo such as `--fail-on hihg` silently disabled the CI gate.
- SARIF describes the extended rule `wp.sqli.param_unprepared` when the result contains it. Before, those results had no rule entry.
- The README is in English. The Polish README moved to `README.pl.md`. The rule reference is in English (`docs/rules.md`) and in Polish (`docs/reguly.md`).
- The package description is in English.
- Tests check that both catalogs have the same keys and the same placeholders.

## 0.3.2

Release prepared for the first publication on the npm registry.

- Install with `npx wpcoderscan` or `npm i -g wpcoderscan`.
- Removed the `wpcs` binary alias. It collided with an existing npm package of that name. The `wpcoderscan` command stays.
- `NOTICE` no longer lists features that are not in the code (CRA mapping and the active module).
- The package description is bilingual, to make the package easier to find in the registry.

## 0.3.1

Fewer false alarms.

- A variable checked against an allowlist before use is no longer tainted. This covers `in_array`, `array_key_exists`, `isset` on an array keyed by a variable, `ctype_*`, `is_numeric`, an anchored regular expression and a comparison with a literal. It works in an `if` body, in `else` after a negation, and after an early exit.
- A Google API key is a heuristic, not a firm finding. It no longer fails the build, because browser maps keys are often public by design.
- `unserialize` with a class list in `allowed_classes` is a medium heuristic instead of a firm finding.
- CI checks the CLI on vulnerable and safe samples, including the `--extended` flag.
- Measurement: on the 200 most popular plugins from wordpress.org (49 thousand PHP files), no firm finding remained except `register_setting`. Recall on the CVE set was unchanged.

## 0.3.0

More input sources and better detection of historical vulnerabilities.

- New sources of user input: `filter_input` without a sanitizing filter, `php://input`, the REST request object (heuristic), `add_query_arg` and `remove_query_arg` without a URL (XSS), and shortcode attributes (stored XSS).
- Array elements are tracked by their literal key. `$a['x']` from `$_GET` no longer taints `$a['y']`.
- XSS: new sinks `printf`, `vprintf`, `die`, `exit`, `wp_die` and `return` in a shortcode callback. `json_encode` responses in these sinks are skipped.
- `wp_ajax_*` and `admin_post_*` handlers can be class methods from the same file. A missing capability check with a nonce present is now medium, a missing nonce is high.
- New `--extended` flag and `extended` input in the GitHub Action. It enables the rule `wp.sqli.param_unprepared` (a function parameter concatenated into a `$wpdb` query without `prepare`).
- Validation on 253 real plugins and themes still shows 0 crashes. New findings are mostly medium heuristics.
- Correction: the first version of this entry quoted before and after recall figures for SQL injection and XSS that counted duplicate CVE records. They were removed. The corrected measurement, on 475 distinct (CVE, plugin, version) pairs from NVD (2023 to 2025), is that 117 of 475 (24.6%) are reported within 25 lines of the vulnerable code and in the same vulnerability class with the default rules, and 139 of 475 (29.3%) with `--extended`. This is recall on known vulnerable versions, not a false-positive rate.

## 0.2.0

Fix suggestions.

- New `--suggest` flag shows a ready code change next to a finding. The scanner writes nothing to source files.
- New `--patch <file>` flag saves complete suggestions as a patch compatible with `git apply`.
- XSS in `echo` and `print`: the escaping function is matched to the HTML context (`esc_html`, `esc_attr`, `esc_url`). Scripts, styles, event attributes and unquoted values get no suggestion.
- `unserialize`: adds `allowed_classes => false` to a single-argument call. The rule no longer reports calls that already have it.
- Every suggestion is verified: parse again, scan again, the finding must disappear and no new ones may appear. Files with syntax errors get no suggestions.
- JSON contains a `patch` field, and SARIF contains a `fixes` field.
- The file's style is preserved: parentheses with or without spaces, `array()` or `[]`, CRLF.

## 0.1.0

First public release.

- Eight rules: SQL injection, REST routes without access control, RCE, `unserialize`, `register_setting`, hardcoded secrets, XSS in `echo` and `print`, and action handlers without a nonce or capability check.
- Lightweight taint analysis within a function. A variable fed from a superglobal is tracked, and casts and sanitizing functions remove the taint.
- Finding confidence: firm findings fail the build, heuristics only warn. The `--strict` flag counts heuristics too.
- Reports: terminal, JSON and SARIF 2.1.0.
- `--diff <ref>` mode for a fast scan of pull request changes.
- GitHub Action (composite) built from the repository source.
- Validation on 253 real WordPress plugins and themes: 0 crashes, about 42 thousand PHP files.
