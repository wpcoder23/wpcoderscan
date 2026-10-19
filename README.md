# WPCoderScan

[![npm](https://img.shields.io/npm/v/wpcoderscan.svg)](https://www.npmjs.com/package/wpcoderscan)
[![CI](https://github.com/wpcoder23/wpcoderscan/actions/workflows/ci.yml/badge.svg)](https://github.com/wpcoder23/wpcoderscan/actions/workflows/ci.yml)

Security scanner for WordPress and PHP code. It finds vulnerabilities in plugins, themes and integrations before they reach production. Built for developers, vendors and agencies, in the age of AI-generated code.

English | [Polski](README.pl.md)

This is an early release (v0.8.0). The architecture and some of the solutions (report, scoring, command-line scanning) come from the ECC and AgentShield projects under the MIT license. The PHP and WordPress rules, the file collector, the parser integration and the mapping to OWASP ASVS and CWE are original. See the `NOTICE` file for the attribution details.

## Quick start

Requires Node.js 18 or newer. The scanner never executes PHP. It reads and parses files, so it is safe to run on code you do not trust.

```bash
npx wpcoderscan ./path-to-plugin
```

You can also install it globally:

```bash
npm i -g wpcoderscan
wpcoderscan ./path-to-plugin
```

Check the version with `--version`. The same scanner runs straight from GitHub, without the npm package:

```bash
npx github:wpcoder23/wpcoderscan ./path-to-plugin
```

or from a local clone of the repository:

```bash
git clone https://github.com/wpcoder23/wpcoderscan.git
cd wpcoderscan
npm install
node dist/cli.js ./path-to-plugin --json
```

## What it detects

The scanner covers eight classes of vulnerabilities, and five more with `--extended`. The rules follow user input inside a function and across calls between functions of the same file. A variable assigned from `$_GET` is tainted. After a numeric cast, `absint` or `escapeshellarg` it is not. `esc_sql` removes the taint only for a value that sits inside quotes in the query.

The scanner treats these as user input:

- superglobals (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, `$_FILES`),
- `filter_input` and `filter_input_array` without a sanitizing filter, and `php://input`,
- the REST request object (`$request->get_param()`, `$request['x']`), as a heuristic, because the route may have validated its arguments,
- shortcode attributes (`$atts` and the keys from `shortcode_atts`), as a source of stored XSS,
- `add_query_arg` and `remove_query_arg` without an explicit URL, in the XSS rule.

Array elements are tracked by their literal key, so `$a['x']` taken from `$_GET` does not taint `$a['y']`.

A variable checked before use stops being tainted. The scanner accepts `in_array`, `array_key_exists`, `isset` on an array keyed by a variable, `ctype_*`, `is_numeric`, an anchored regular expression, a regular expression that rejects any character outside a set, a comparison with a literal and a validator named like `is_valid_*` or `validate_*`. This works in the body of an `if`, in the branches of a ternary, in the `else` branch after a negation, and after an early exit (`return`, `die`, `wp_die`). The scanner does not judge whether the allowlist itself is correct.

- SQL injection: `$wpdb` queries built from user input without `prepare`. A superglobal directly in the query is firm. A variable fed from a superglobal is a heuristic. `prepare` protects only the values passed to it, so user input pasted into the query text is still reported. So is `esc_sql` used outside quotes (a number, a column, `ORDER BY`).
- REST: a route without `permission_callback` (firm). `__return_true` on a route that changes data (heuristic). Read-only routes are skipped.
- RCE: `eval`, `include` and `require` with a path from the user, template loaders given a name from the user (`get_template_part`, `load_template`), backticks, the `exec` and `shell_exec` family. Data straight from a superglobal is firm, data through a variable is a heuristic.
- Deserialization: `unserialize` and `maybe_unserialize` on a superglobal (firm) or on a variable fed from user input (heuristic).
- Options: `register_setting` without `sanitize_callback` (firm).
- Secrets: provider keys (AWS, Stripe, GitHub, Slack, SendGrid, a private key with its body) are firm. A Google API key and detection by variable name are heuristics, because browser maps keys are often public by design.
- XSS: user input in `echo`, `print`, `printf`, `die`, `wp_die` and in the value returned by a shortcode, without `esc_*`, `wp_kses`, `sanitize_*` or a cast (heuristic).
- Nonce and capabilities: `admin_post_*` and `wp_ajax_*` handlers that change state without a nonce check or without `current_user_can` (heuristic). The handler can be a function, a closure or a class method from the same file. A missing capability check with a nonce present is medium severity, and missing both is high.

Extended mode (`--extended`) adds six rules. They are off by default, because they match real bugs and also a lot of safe code, so you have to ask for them.

- `wp.sqli.param_unprepared`: a function parameter concatenated into a `$wpdb` query without `prepare`. The scanner cannot see the callers in other files, so this is a medium-severity warning.
- `wp.file.path_traversal`: a file read, written or deleted at a path from user input (`file_get_contents`, `unlink`, `file_put_contents`, `copy`, `$wp_filesystem` and others). A path reduced with `basename` or checked with `realpath` is not reported.
- `wp.http.ssrf`: an HTTP request to an address from user input (`wp_remote_get`, `curl_init`, `fsockopen`). User data appended after a fixed host is not reported, and `wp_safe_remote_*` is outside the rule.
- `wp.upload.unrestricted`: an uploaded file saved under the client's name without a file type check, or `wp_handle_upload` with `test_type` turned off.
- `wp.privilege.escalation`: the role, the login or the capabilities of an account taken from the request (`wp_insert_user`, `set_role`, `update_user_meta`, `wp_set_auth_cookie`).
- `wp.option.arbitrary_update`: an option name taken from user input (`update_option( $_POST['name'], ... )`).

Code that only an administrator can reach is not an open door for a visitor. The file, request and upload rules give it only a low-severity hint, and the account and option rules stay quiet. The scanner reads as a gate an administrator capability check, a menu page or a REST route registered with one, a hook registered only under such a check, a permission function named like an administrator check, and a helper that the same file calls only from code behind such a gate. A nonce is not a gate. The details are in [docs/rules.md](docs/rules.md#administrator-gate).

A full description of every rule with vulnerable and correct code examples is in [docs/rules.md](docs/rules.md).

Every finding gets a severity (critical, high, medium, low), a confidence level, a location in the code and a fix hint. Results are mapped to OWASP ASVS and CWE.

The scanner skips the directories `vendor`, `vendor-prefixed`, `node_modules`, `.git`, `dist` and `build`.

## Confidence and the CI gate

Every finding has a confidence level. **Firm** findings are structurally unambiguous and fail the build. **Heuristic** findings can be false alarms, so by default they only warn and do not fail CI. The `--strict` flag makes heuristics count toward the exit code too.

`wpcoderscan` exits with code `1` when it finds a vulnerability at the level set by `--fail-on` (default `high`) or higher, following the confidence rule above. That makes it usable as a CI gate. Code `2` means a scanner error or a bad argument.

## Language

Output is in English by default. Polish is available with `--lang pl` or the environment variable `WPCODERSCAN_LANG=pl`. The flag wins over the variable. The language applies to the terminal report, JSON and SARIF messages, fix hints and errors. Rule IDs and JSON keys never change.

```bash
npx wpcoderscan ./path-to-plugin --lang pl
```

## Measured results

The scanner is measured on known vulnerabilities and on popular plugins. The main set has 475 pairs of a CVE and a vulnerable plugin version, from 2023 to 2025. The rules were written while this set was visible, so it shows how well they fit known bugs.

- Default mode reports a finding of the right class within 25 lines of the CVE line in 173 of 475 cases (36.4%). With `--extended` it is 191 of 475 (40.2%).
- A blind test uses 618 pairs from CVEs published in 2026. No rule was written against them. Default mode reports the right class within 25 lines of the CVE line in 80 cases (12.9%), and `--extended` in 129 (20.9%). Version 0.7.0 gets 73 (11.8%) and 121 (19.6%) on the same set. Expect numbers like these on new code. The visible set flatters the scanner.
- A second set of 301 pairs covers the classes of the five rules that `--extended` added in 0.6.0. With `--extended` the scanner reports the right class within 25 lines of the CVE line in 62 of 301 cases (20.6%). Without the new rules the same scan reports 14 (4.7%). The rules were tuned while this set was visible, so it is not a blind test. The same classes in the 2026 CVEs, 440 pairs, give 46 (10.5%) with the new rules and 13 (3.0%) without them.
- On the 200 most popular free plugins from wordpress.org, 198 of which still download (49 thousand PHP files), 100 plugins have no finding in the default mode. The median is zero findings per plugin and the default mode prints 517 findings. With `--extended` the median is one, and the five new rules add 52 findings in 23 plugins.

Many of the misses are XSS bugs whose data flow crosses files. The scanner follows calls only inside a file. About a quarter of the 517 findings on the popular plugins are false alarms, and about two thirds are accurate but low risk, for example a public endpoint that is public by design. Few are real weaknesses. A hand review counted them. The method, the counts, the data and the scripts are in [benchmark/](benchmark/README.md). You can run the measurements again.

## Limitations

Data flow analysis works inside a file. It follows calls between functions and methods of the same file, up to six levels deep. It does not follow flow between files and does not know a project's own sanitizing functions. Callbacks registered in a different file than their definition stay unresolved. The scanner knows in which branch of an `if`, `switch`, loop or `catch` a write sits, but it does not evaluate conditions. A flag that picks the branch, and an early `return` or `exit` inside a branch, are not understood. No alarm does not prove that the code is safe. The scanner does not replace a code review or a penetration test.

## Fix suggestions

For two rules the scanner can produce a ready change: XSS in `echo` and `print`, and `unserialize` on user input. The scanner never writes to your files. It shows the change or saves it as a patch, and the decision is yours.

- `--suggest` shows what to change next to each finding, as before and after lines.
- `--patch fixes.patch` saves all complete suggestions as one patch. Run the scan from the repository root, then: `git apply --check fixes.patch && git apply fixes.patch`.
- JSON contains a `patch` field on a finding, and SARIF contains a `fixes` field.

The scanner picks the escaping function to match the place in the HTML. In page content that is `esc_html()`, in a quoted attribute `esc_attr()`, and for a whole `href` or `src` value `esc_url()`. For `unserialize` it adds `allowed_classes => false`. It keeps the file's style: spaces inside parentheses, `array()` or `[]`, CRLF line endings.

The scanner verifies every suggestion before showing it. It applies the change in memory, parses the code again, scans it once more and drops the suggestion if the finding does not disappear or a new one appears. It also drops it when the file has syntax errors.

Anything that needs a decision about context gets no suggestion: scripts, styles, event attributes, unquoted values, and a URL where the data comes first and more text follows. A suggestion marked "needs a decision" appears only with `--suggest`. It never goes into the patch. This happens when the HTML context cannot be read from the code, and the scanner proposes `esc_html()`.

SQL injection, RCE, missing access control and hardcoded secrets are deliberately not fixed by the scanner, because the correct change depends on the project.

## Adopt it in an existing codebase

A scanner that reports hundreds of old findings on the first day gets switched off. Three tools let you start with a clean gate and fix the old findings over time.

### Baseline

Save today's findings once. From then on the scanner reports, and fails the build, only on new findings.

```bash
npx wpcoderscan . --write-baseline .wpcoderscan-baseline.json
npx wpcoderscan . --baseline .wpcoderscan-baseline.json
```

Commit the file. A finding matches by rule, file, the text of its line and its number among identical lines. It does not match by line number, so moving code around does not bring old findings back. When you fix an old finding, its entry goes stale. The report says how many entries have no match, and `--write-baseline` refreshes the file.

`--write-baseline` always scans from scratch, writes the file and exits with code 0. It cannot be combined with `--diff`, because the baseline would cover only the changed files. Run every scan from the same directory, because the file stores paths relative to the working directory.

### Ignore comments

Mark a finding that was reviewed and accepted.

```php
// wpcoderscan-ignore wp.rce.dynamic -- the template name comes from a fixed list
include $path;

$rows = $wpdb->get_results( $sql ); // wpcoderscan-ignore wp.sqli.unprepared -- $sql is built from casts

// wpcoderscan-ignore-file wp.secret.hardcoded -- public demo key
```

- A comment on its own line covers the next line. A comment after code covers its own line. `wpcoderscan-ignore-file` covers the whole file. Use `//`, `#` or `/* */`.
- The rule id is required. List several ids separated by commas, or use `*`, for example `wp.xss.*`.
- A comment without a rule id suppresses nothing and appears as a warning. So does an id that matches no rule, which catches typos.
- Text after ` -- ` is the reason.
- The report always says how many findings comments suppressed. JSON lists them under `suppressed`, and SARIF carries the count in the run properties. GitHub does not honor suppressions inside SARIF, so suppressed findings are not in the SARIF results.
- When you audit someone else's code, add `--no-ignore-comments`. Otherwise its author can hide findings with a comment.

### Settings file

`.wpcoderscan.json` in the current directory holds the same options as the flags, so a team shares one setup.

```json
{
  "failOn": "high",
  "strict": false,
  "extended": false,
  "lang": "en",
  "exclude": ["tests/", "legacy/", "*.min.php"],
  "rules": { "wp.auth.unprotected_action": "off" },
  "baseline": ".wpcoderscan-baseline.json",
  "ignoreComments": true
}
```

- A flag beats an environment variable, the variable beats the file, and the file beats the default.
- The scanner reads the file only from the current directory, or from the path given in `--config`. It never reads one from the scanned code, so a plugin you check cannot switch rules off. `--no-config` skips the file.
- `exclude` takes simple path patterns relative to the settings file: `*`, `**` and `?`. A name without a slash matches at any depth. A leading `/` anchors the pattern to the directory of the settings file. A trailing `/` matches directories only.
- `rules` can only switch a rule `off`. A name can use `*`. A name that matches no rule gives a warning.
- `baseline` is a path relative to the settings file.
- An unknown option or a wrong type is an error with exit code 2, so a typo cannot quietly weaken the gate.

The settings file, the baseline file and the comments live in the repository, so a pull request can change them. Review those changes like code. A `CODEOWNERS` entry for the first two files helps.

## Output formats

- Terminal (default), a readable report with a score.
- `--json`, for further processing.
- `--sarif`, SARIF 2.1.0 for the GitHub Security tab.
- `--diff <ref>`, scan only PHP files changed against a git ref (a fast scan for pull requests).
- `--suggest` and `--patch <file>`, fix suggestions (described above).
- `--extended`, additional rules with lower precision (described above).
- `--lang <en|pl>`, output language (described above).
- `--write-baseline <file>` and `--baseline <file>`, report only findings that are new (described above).
- `--config <file>` and `--no-config`, the settings file (described above).
- `--no-ignore-comments`, do not honor `wpcoderscan-ignore` comments (described above).

## GitHub Action

Scan on every push and pull request, with results in the Security tab. The action builds the scanner from the repository source at the tag you pin, so it does not need the npm package. A ready example is in `examples/github-workflow.yml`. A live demo with results in the Security tab: [wpcoder23/wpcoderscan-demo](https://github.com/wpcoder23/wpcoderscan-demo). A minimal workflow:

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: wpcoder23/wpcoderscan@v0.8.0
        with:
          path: .
          fail-on: high
          # extended: 'true'   # additional rules with lower precision
          # lang: pl           # Polish messages (default: en)
          # baseline: .wpcoderscan-baseline.json   # report only findings that are not in this file
          # config: .wpcoderscan.json              # settings file, if it is not in the repository root
```

The action reads `.wpcoderscan.json` from the repository root, like the command line does. A `fail-on` or `lang` set in the workflow wins over the file. Leave them out when the file should decide.

## License

Apache-2.0. The core is open. Adapted portions of MIT-licensed projects keep their own license notice. See the `LICENSE` and `NOTICE` files.
