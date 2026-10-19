# Changelog

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
