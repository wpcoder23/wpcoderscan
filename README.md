# WPCoderScan

[![npm](https://img.shields.io/npm/v/wpcoderscan.svg)](https://www.npmjs.com/package/wpcoderscan)
[![CI](https://github.com/wpcoder23/wpcoderscan/actions/workflows/ci.yml/badge.svg)](https://github.com/wpcoder23/wpcoderscan/actions/workflows/ci.yml)

Security scanner for WordPress and PHP code. It finds vulnerabilities in plugins, themes and integrations before they reach production. Built for developers, vendors and agencies, in the age of AI-generated code.

English | [Polski](README.pl.md)

This is an early release (v0.4.0). The architecture and some of the solutions (report, scoring, command-line scanning) come from the ECC and AgentShield projects under the MIT license. The PHP and WordPress rules, the file collector, the parser integration and the mapping to OWASP ASVS and CWE are original. See the `NOTICE` file for the attribution details.

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

The scanner covers eight classes of vulnerabilities. The rules follow user input within a single function. A variable assigned from `$_GET` is tainted. After a numeric cast, `absint`, `esc_sql` or `escapeshellarg` it is not.

The scanner treats these as user input:

- superglobals (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, `$_FILES`),
- `filter_input` and `filter_input_array` without a sanitizing filter, and `php://input`,
- the REST request object (`$request->get_param()`, `$request['x']`), as a heuristic, because the route may have validated its arguments,
- shortcode attributes (`$atts` and the keys from `shortcode_atts`), as a source of stored XSS,
- `add_query_arg` and `remove_query_arg` without an explicit URL, in the XSS rule.

Array elements are tracked by their literal key, so `$a['x']` taken from `$_GET` does not taint `$a['y']`.

A variable checked before use stops being tainted. The scanner accepts `in_array`, `array_key_exists`, `isset` on an array keyed by a variable, `ctype_*`, `is_numeric`, an anchored regular expression and a comparison with a literal. This works in the body of an `if`, in the `else` branch after a negation, and after an early exit (`return`, `die`, `wp_die`). The scanner does not judge whether the allowlist itself is correct.

- SQL injection: `$wpdb` queries built from user input without `prepare`. A superglobal directly in the query is firm. A variable fed from a superglobal is a heuristic.
- REST: a route without `permission_callback` (firm). `__return_true` on a route that changes data (heuristic). Read-only routes are skipped.
- RCE: `eval`, `include` and `require` with a path from the user, backticks, the `exec` and `shell_exec` family. Data straight from a superglobal is firm, data through a variable is a heuristic.
- Deserialization: `unserialize` and `maybe_unserialize` on a superglobal (firm).
- Options: `register_setting` without `sanitize_callback` (firm).
- Secrets: provider keys (AWS, Stripe, GitHub, Slack, SendGrid, a private key with its body) are firm. A Google API key and detection by variable name are heuristics, because browser maps keys are often public by design.
- XSS: user input in `echo`, `print`, `printf`, `die`, `wp_die` and in the value returned by a shortcode, without `esc_*`, `wp_kses`, `sanitize_*` or a cast (heuristic).
- Nonce and capabilities: `admin_post_*` and `wp_ajax_*` handlers that change state without a nonce check or without `current_user_can` (heuristic). The handler can be a function, a closure or a class method from the same file. A missing capability check with a nonce present is medium severity, and missing both is high.

Extended mode (`--extended`) adds the rule `wp.sqli.param_unprepared`: a function parameter concatenated into a `$wpdb` query without `prepare`. The scanner cannot see the callers, so this is a medium-severity warning and it is off by default. It matches many historical SQL injection bugs and also a lot of safe code, so you have to ask for it.

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

## Limitations

Data flow analysis works within a single function and a single file. It does not follow flow between functions or files and does not know a project's own sanitizing functions. Callbacks registered in a different file than their definition stay unresolved. No alarm does not prove that the code is safe. The scanner does not replace a code review or a penetration test.

## Fix suggestions

For two rules the scanner can produce a ready change: XSS in `echo` and `print`, and `unserialize` on user input. The scanner never writes to your files. It shows the change or saves it as a patch, and the decision is yours.

- `--suggest` shows what to change next to each finding, as before and after lines.
- `--patch fixes.patch` saves all complete suggestions as one patch. Run the scan from the repository root, then: `git apply --check fixes.patch && git apply fixes.patch`.
- JSON contains a `patch` field on a finding, and SARIF contains a `fixes` field.

The scanner picks the escaping function to match the place in the HTML. In page content that is `esc_html()`, in a quoted attribute `esc_attr()`, and for a whole `href` or `src` value `esc_url()`. For `unserialize` it adds `allowed_classes => false`. It keeps the file's style: spaces inside parentheses, `array()` or `[]`, CRLF line endings.

The scanner verifies every suggestion before showing it. It applies the change in memory, parses the code again, scans it once more and drops the suggestion if the finding does not disappear or a new one appears. It also drops it when the file has syntax errors.

Anything that needs a decision about context gets no suggestion: scripts, styles, event attributes, unquoted values, and a URL where the data comes first and more text follows. A suggestion marked "needs a decision" appears only with `--suggest`. It never goes into the patch. This happens when the HTML context cannot be read from the code, and the scanner proposes `esc_html()`.

SQL injection, RCE, missing access control and hardcoded secrets are deliberately not fixed by the scanner, because the correct change depends on the project.

## Output formats

- Terminal (default), a readable report with a score.
- `--json`, for further processing.
- `--sarif`, SARIF 2.1.0 for the GitHub Security tab.
- `--diff <ref>`, scan only PHP files changed against a git ref (a fast scan for pull requests).
- `--suggest` and `--patch <file>`, fix suggestions (described above).
- `--extended`, additional rules with lower precision (described above).
- `--lang <en|pl>`, output language (described above).

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
      - uses: wpcoder23/wpcoderscan@v0.4.0
        with:
          path: .
          fail-on: high
          # extended: 'true'   # additional rules with lower precision
          # lang: pl           # Polish messages (default: en)
```

## License

Apache-2.0. The core is open. Adapted portions of MIT-licensed projects keep their own license notice. See the `LICENSE` and `NOTICE` files.
