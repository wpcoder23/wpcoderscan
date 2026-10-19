# Benchmark

These scripts measure four things. You can rerun all of them.

- **Recall on known vulnerabilities.** How many historical WordPress plugin CVEs does the scanner report?
- **Recall on the classes of the 0.6.0 rules.** The same question for file paths, SSRF, uploads, privilege escalation and options, on a second set of CVEs.
- **Noise on popular plugins.** How many findings does the scanner print for the 200 most popular free plugins?
- **Recall on fresh CVEs.** The same two recall questions on CVEs published in 2026, which the rules were not written against. This is the blind test.

A fifth thing is judged by hand and not by a script: how many of the findings are right. It is described under the latest numbers.

The recall and noise numbers published with each release are measured this way.

## How recall is measured

The CVE snapshot is in `data/cves.json`. It holds CVEs from 2023 to 2025 that the NVD links to a file and a line in the plugin's Trac repository. That gives the vulnerable file and line for each CVE.

For each plugin version the script:

1. Downloads the vulnerable version from wordpress.org.
2. Scans it.
3. Checks whether the scanner reported a finding of the matching class (SQL injection, XSS, PHP object injection, file inclusion, missing authorization).

The unit is a unique (CVE, plugin, version) pair. Three results are counted:

- **near.** A finding of the matching class within 25 lines of the CVE line, in the same file. This is the strict measure and the headline number.
- **func.** A near hit, or a finding of the matching class anywhere in the innermost function, method or closure that contains the CVE line. It credits a finding at the start of a long handler when the CVE line points at the sink at its end. It was added in 0.8.0, before the blind measurement of that version. It is always reported next to near, never instead of it.
- **file.** A finding of the matching class anywhere in that file.

So near is never larger than func, and func is never larger than file.

CSRF and CVEs outside these classes are skipped. Stored XSS is the largest class in the NVD and the hardest for a static scanner, so only its first 80 entries are used. This keeps it from drowning the other classes.

## How recall is measured for the 0.6.0 classes

The main set has few CVEs of the classes that the five `--extended` rules of 0.6.0 look for: file paths, SSRF, uploads, privilege escalation and options. A second set covers them. It is in `data/cves-extra.json`: 326 CVE entries in 284 plugin versions. `fetch-cves-extra.mjs` builds it from the NVD the same way as the main set. The measured classes are file upload, file read, file delete, SSRF, privilege escalation, authentication bypass, option update and remote code execution. They give 302 unique pairs. Open redirects and other classes are skipped. One version (`liquid-chatgpt` 1.0.1) no longer downloads, so the measurement covers 301 pairs.

`recall-extra.mjs` scans each version once with `--extended`. It counts near and file hits as above, and it counts them twice:

- **Before.** Only the rules that existed before the new family count. That is `wp.rce.dynamic` for remote code execution, and the rules for missing authorization (`wp.auth.unprotected_action`, `wp.rest.no_permission_callback`) for privilege escalation and authentication bypass.
- **After.** The new rules count as well. File upload adds the upload and path rules. File read and file delete add the path rule. SSRF adds the SSRF rule. Privilege escalation adds the account and option rules. Authentication bypass adds the account rule. Option update adds the option rule.

The mapping from the CVE class to the rules is written at the top of the script. It was fixed before the first measurement. For five of the eight classes there was no rule before, so their "before" column is zero by construction. The comparison says something only for the other three.

## How the blind test works

The main set and the second set were visible while the rules were written and tuned. Their numbers say how well the rules fit known bugs. They do not say how the scanner does on bugs it has not seen. Two more sets are for that. They hold CVEs published from 2026-01-06 to 2026-10-17. The scripts that fetch them are the ones that built the visible sets, with a different date range.

- `data/cves-2026.json`, the classes of the main set: 1 439 CVE entries.
- `data/cves-extra-2026.json`, the classes of the second set: 467 entries.

Pass a set with `--data cves-2026.json`. The rules for using them:

- A set is measured with frozen rules, on a release build, never on a build in progress.
- Only totals are recorded. The result files are not opened and the misses are not read.
- No rule is tuned on a miss from these sets. Fixes come from the misses of the 2023 to 2025 sets.
- Each release is measured once. 0.8.0 was measured on its release build. 0.7.0 was measured on the same sets during the work on 0.8.0, only to have a baseline, and only the totals were read.

This is blind in one sense only. The bug classes repeat every year, so a rule written against 2023 to 2025 can still fit a 2026 bug, and that is what the test measures. But a set that has informed one release decision is no longer fresh for the next, so the sets lose value with each use. Treat the result as a better estimate than the visible sets, not as a clean one.

## How noise is measured

The script scans the plugins listed in `data/popular.json`. That is a frozen list of the 200 most popular free plugins on 2026-10-19. A frozen list makes two scanner versions comparable. Pass `--live` to fetch the current list instead.

It prints the median and the 90th percentile of findings per plugin, the number of plugins without findings, and the count per rule. The median must stay low. In the default mode it is 0 since 0.8.0. Pass `--extended` to count the findings of the extended rules as well. The median is then 1.

Two versions on the frozen list no longer download. On 2026-10-19 wordpress.org answers 404 for `duplicate-page` 4.5.9 and `wp-file-manager` 8.0.6. A run from scratch therefore scans 198 plugins (48 977 PHP files). The numbers below come from such a run. The 0.5.0 release notes give 580 findings and 97 plugins without a finding. That run had all 200 versions, as they were available then.

## Latest numbers

Scanner 0.8.0 against 0.7.0. Every count is a unique pair of a CVE and a plugin version.

### Main set, visible

The main set has 475 pairs: 445 CVE ids in 465 plugin versions. Another 17 versions could not be downloaded and are left out. The rules were written while this set was visible.

| | 0.7.0 | 0.8.0 |
| --- | --- | --- |
| Default mode, near | 144 of 475 (30.3%) | 173 of 475 (36.4%) |
| Default mode, func | 166 of 475 (34.9%) | 201 of 475 (42.3%) |
| Default mode, file | 188 of 475 (39.6%) | 222 of 475 (46.7%) |
| `--extended`, near | 162 of 475 (34.1%) | 191 of 475 (40.2%) |
| `--extended`, func | 185 of 475 (38.9%) | 220 of 475 (46.3%) |
| `--extended`, file | 214 of 475 (45.1%) | 248 of 475 (52.2%) |
| Findings on 198 popular plugins | 579 | 517 |
| Median findings per plugin | 1 | 0 |
| 90th percentile | 6 | 6 |
| Plugins without findings | 96 | 100 |

The func numbers of 0.7.0 were measured afterwards on the frozen 0.7.0 build, because the metric did not exist when 0.7.0 was released. Its near and file numbers are the ones from its release.

Near hits by class:

| Class | Pairs | Default, 0.7.0 | Default, 0.8.0 | `--extended`, 0.7.0 | `--extended`, 0.8.0 |
| --- | --- | --- | --- | --- | --- |
| SQL injection | 98 | 24 | 25 | 42 | 43 |
| Reflected XSS | 183 | 74 | 98 | 74 | 98 |
| Stored XSS | 85 | 21 | 22 | 21 | 22 |
| Missing authorization | 54 | 12 | 15 | 12 | 15 |
| File inclusion | 30 | 9 | 9 | 9 | 9 |
| PHP object injection | 25 | 4 | 4 | 4 | 4 |

The authorization row gains four pairs and loses one (CVE-2025-11758, see below).

### Main classes, 2026 CVEs, blind

The same classes, on CVEs published from 2026-01-06 to 2026-10-17. The list holds 635 plugin versions. 54 of them could not be scanned and are left out, which leaves 618 pairs. No rule was written against this set. 0.8.0 was measured on it once, on the release build.

| | 0.7.0 | 0.8.0 |
| --- | --- | --- |
| Default mode, near | 73 of 618 (11.8%) | 80 of 618 (12.9%) |
| Default mode, func | 77 of 618 (12.5%) | 87 of 618 (14.1%) |
| Default mode, file | 102 of 618 (16.5%) | 118 of 618 (19.1%) |
| `--extended`, near | 121 of 618 (19.6%) | 129 of 618 (20.9%) |
| `--extended`, func | 131 of 618 (21.2%) | 142 of 618 (23.0%) |
| `--extended`, file | 185 of 618 (29.9%) | 200 of 618 (32.4%) |

Near hits by class, default mode:

| Class | Pairs | 0.7.0 | 0.8.0 |
| --- | --- | --- | --- |
| SQL injection | 244 | 24 | 26 |
| Missing authorization | 137 | 17 | 20 |
| File inclusion | 39 | 3 | 3 |
| Reflected XSS | 105 | 15 | 16 |
| Stored XSS | 68 | 12 | 13 |
| PHP object injection | 25 | 2 | 2 |

With `--extended` the SQL injection row is 72 for 0.7.0 and 75 for 0.8.0. The extended mode adds the rule for unprepared parameters. The other rows stay the same.

The visible set gained 29 pairs in the default mode, which is 6.1 points. The blind set gained 7 pairs, which is 1.1 points. The scanner fits the bugs it was tuned on better than the bugs it has not seen. Expect a gain of about one point on new code.

### Classes of the 0.6.0 rules, visible and 2026

The second set, scanned with `--extended`. Near hits without and with the five rules of 0.6.0. The left block is the visible set of 301 pairs, which the rules were tuned on. The right block is the set of 2026 CVEs. Its list holds 444 plugin versions, 14 could not be scanned, and 440 pairs remain.

| Class | Pairs | Before | After | 2026 pairs | Before | After |
| --- | --- | --- | --- | --- | --- | --- |
| File upload | 84 | 0 | 13 | 63 | 0 | 6 |
| File read | 22 | 0 | 2 | 69 | 0 | 8 |
| File delete | 27 | 0 | 9 | 51 | 0 | 2 |
| Remote code execution | 29 | 5 | 5 | 48 | 4 | 4 |
| Authentication bypass | 40 | 2 | 8 | 51 | 2 | 3 |
| SSRF | 23 | 0 | 8 | 41 | 0 | 7 |
| Privilege escalation | 70 | 7 | 16 | 117 | 7 | 16 |
| Option update | 6 | 0 | 1 | 0 | - | - |
| All | 301 | 14 (4.7%) | 62 (20.6%) | 440 | 13 (3.0%) | 46 (10.5%) |

In the visible set the func hits go from 16 (5.3%) to 68 (22.6%) and the file hits from 31 (10.3%) to 90 (29.9%). In the 2026 set the func hits go from 13 (3.0%) to 48 (10.9%) and the file hits from 24 (5.5%) to 75 (17.0%). 0.7.0 scores 12 (2.7%) before and 44 (10.0%) after on the 2026 set. The visible set shows about 20%, the blind set about 10%. The second figure is the one to expect on new code.

### Noise on the popular plugins

198 of the 200 plugins, 48 977 PHP files. Default mode, findings per rule:

| Rule | 0.7.0 | 0.8.0 | Plugins in 0.8.0 |
| --- | --- | --- | --- |
| `wp.option.no_sanitize_callback` | 281 | 281 | 38 |
| `wp.auth.unprotected_action` | 164 | 88 | 36 |
| `wp.rest.no_permission_callback` | 47 | 47 | 25 |
| `wp.xss.echo_superglobal` | 36 | 46 | 18 |
| `wp.rce.dynamic` | 29 | 29 | 13 |
| `wp.secret.hardcoded` | 18 | 18 | 12 |
| `wp.sqli.unprepared` | 1 | 4 | 2 |
| `wp.unserialize.user_input` | 3 | 4 | 2 |
| All | 579 | 517 | 98 |

With `--extended` on the same plugins, 0.8.0 gives 819 findings (0.7.0: 871). 124 plugins have a finding and 74 do not. The median is 1 and the 90th percentile is 10. The five rules of 0.6.0 give 52 of those findings in 23 plugins, and all of them are heuristics: 28 for file paths in 8 plugins, 8 for SSRF in 7, 10 for option names in 7, 6 for privilege escalation in 3 and none for uploads. The older extended rule `wp.sqli.param_unprepared` gives 250 findings in 49 plugins.

### Precision, judged by hand

The tables above count findings. They do not say how many are right. For 0.8.0 a reviewer read the 517 findings of the default mode on the 198 popular plugins, each with the code around it, and put every one in one of four groups:

- **Real weakness.** The code has a flaw that someone with the access the code allows can use.
- **Accurate, low risk.** The finding describes the code correctly, but little can go wrong. The endpoint is public on purpose, the action is harmless, or only an administrator reaches it.
- **False alarm.** The finding does not describe the code correctly. A guard exists that the rule did not see, or the value is not a secret.
- **Unclear.** The reviewer could not decide.

| Rule | Findings | Real | Low risk | False alarm | Unclear |
| --- | --- | --- | --- | --- | --- |
| `wp.option.no_sanitize_callback` | 281 | 0 | 200 | 81 | 0 |
| `wp.auth.unprotected_action` | 88 | 25 | 45 | 18 | 0 |
| `wp.rest.no_permission_callback` | 47 | 0 | 47 | 0 | 0 |
| `wp.xss.echo_superglobal` | 46 | 1 | 18 | 26 | 1 |
| `wp.rce.dynamic` | 29 | 0 | 27 | 2 | 0 |
| `wp.secret.hardcoded` | 18 | 1 | 10 | 7 | 0 |
| `wp.sqli.unprepared` | 4 | 0 | 1 | 3 | 0 |
| `wp.unserialize.user_input` | 4 | 0 | 4 | 0 | 0 |
| All | 517 | 27 (5.2%) | 352 (68.1%) | 137 (26.5%) | 1 (0.2%) |

Read the table with these limits in mind.

- One reviewer judged the findings, and the same reviewer wrote the rules. A second reviewer would move some findings between "low risk" and "false alarm".
- The 281 option findings were not read one by one. They were sorted by the shape of the `register_setting` call, and 20 were read by hand. 81 of them pass a callable array such as `[ $this, 'sanitize' ]` as the third argument. WordPress accepts a callable there and uses it as the sanitize callback (checked in the source of WordPress 6.9.4), so the rule is wrong for these 81. They are the largest single group of false alarms. The number 81 is a lower bound for that row.
- The study covers the default mode. The 52 findings of the five `--extended` rules and the 250 of `wp.sqli.param_unprepared` were not read again.
- The real weaknesses are mostly handlers that check a nonce but no capability. There is also a hardcoded encryption key and a shortcode attribute that reaches the page unescaped. The reviewer did not find one that lets an anonymous visitor take over a site. The plugins are not named here.

So the shares are rough. About one finding in twenty is a real weakness, about two in three are accurate but low risk, and about one in four is a false alarm.

## What these numbers do not say

- The precision shares are one reviewer's judgement on one run, in the default mode. They are not a false-positive rate for your code. Popular plugins are also better kept than the average plugin, so the shares on other code may differ.
- A finding near a CVE line can be a different bug of the same class.
- Part of the gain is heuristic findings. The default mode reports firm findings and heuristics together.
- The gain on the visible set is mostly fit, because the rules were written while that set was visible. The blind set gained 7 pairs, not 29. A difference of 7 pairs in 618 is small. Quote it as about one point, not as a precise figure.
- The 25-line window is a choice. A correct finding 30 lines from the CVE line counts as func or file, not near.
- Reflected and stored XSS make up most of the main set. Most of the XSS bugs that are still missed need the data flow across files, which the scanner does not follow.
- The sample covers only CVEs that link to a Trac line. It is not a random sample of all plugin bugs.
- Authorization pairs move in both directions between versions. Three pairs from 0.4.0 stopped being near hits in 0.5.0, because the rule started to report at the handler definition, not at the `add_action` line. In 0.8.0 two of them are near hits again: CVE-2025-5304 (project-notebooks 1.1.3) and CVE-2025-13403 (employee-spotlight 5.1.3). The third, CVE-2025-14366 (eyewear-prescription-form 6.0.1), is a func hit.
- 0.8.0 loses one pair of the main set: CVE-2025-11758 (aio-time-clock-lite 2.0.1). Its handlers are registered for visitors too, with the same callback, and the rule reads that as public by design.
- The second set was visible while the five rules of 0.6.0 were tuned. The mapping from the CVE class to the rules was fixed before the first measurement, but the rules were adjusted afterwards to fit what the set showed. That is why the 2026 numbers are about half of the visible ones.
- For five of the eight classes of the second set, and four of the seven in the 2026 set, the "before" column is zero by construction, because no rule existed. Only remote code execution, authentication bypass and privilege escalation compare old rules with new ones.
- The precision of the five rules of 0.6.0 was judged by reading their findings by hand when they were added: 43 on 252 plugins and themes from a local disk (42 151 PHP files) and 43 on the 198 popular plugins. That is a review, not a rate. The 52 findings of 0.8.0 were not read again. Some of the findings that remain are by design, for example an administrator tool that writes files on purpose.
- The new rules still raise false alarms in a few known cases. A dispatcher checks the capability once and then calls handlers from a table. A capability sits in a constant or a property that another file defines. A REST route validates its arguments in the route definition. A container key is checked before it is stored. A gate sits in another file.
- One pair of the second set is missed because of a limit of the upload rule: CVE-2023-6827 (essential-real-estate 4.3.5). The rule counts an extension check on zip entries after the save, followed by a delete, as validation.
- A firm finding of a new rule fails the build under `--extended` at the default `--fail-on high`. All 52 findings of the five rules on the popular plugins are heuristics, so they only warn.

## How to run

Node 18 or newer, and `tar` or `unzip` on the PATH. From the repository root:

```
npm ci
npm run build
node benchmark/run.mjs --label current
```

The first run downloads about a thousand archives into `benchmark/.cache`. Later runs reuse them. The run takes about a quarter of an hour. It measures the main set (default and `--extended`), the second set and the noise on the popular plugins (default and `--extended`).

To compare with an older release, build that release in a separate clone and point `--lib` at its `dist/index.js`:

```
node benchmark/run.mjs --lib /path/to/old/dist/index.js --label base
node benchmark/compare.mjs --base base --cand current --new
```

`compare.mjs` prints the change per class, the pairs that stopped matching, the change in noise per rule and, with `--new`, the findings that did not exist before. Read the new findings. They show where precision may have dropped.

Single parts, if you need them:

```
node benchmark/recall.mjs --lib dist/index.js --out benchmark/results/x-recall.json [--extended] [--window 25] [--max 1000] [--data cves-2026.json]
node benchmark/recall-extra.mjs --lib dist/index.js --out benchmark/results/x-recall-extra.json [--window 25] [--data cves-extra-2026.json]
node benchmark/noise.mjs --lib dist/index.js --out benchmark/results/x-noise.json [--extended] [--live]
node benchmark/fetch-cves.mjs --from 2023 --to 2025
node benchmark/fetch-cves-extra.mjs --from 2023 --to 2025
```

The blind sets are not part of `run.mjs`. Measure them with `recall.mjs --data cves-2026.json` (add `--extended` for the extended mode) and `recall-extra.mjs --data cves-extra-2026.json`, on a release build, and read only the totals.

`fetch-cves.mjs` and `fetch-cves-extra.mjs` refresh the CVE snapshots from the NVD. The NVD limits the request rate, so each takes about an hour. The snapshots in the repository are enough to reproduce the numbers above.

## Safety

The plugin archives are untrusted code. The scripts only download, unpack and parse them. They never run anything from them, and they unpack into `benchmark/.cache`, which is git-ignored.
