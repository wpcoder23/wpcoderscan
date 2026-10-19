# Benchmark

These scripts measure three things. You can rerun all of them.

- **Recall on known vulnerabilities.** How many historical WordPress plugin CVEs does the scanner report?
- **Recall on the classes of the 0.6.0 rules.** The same question for file paths, SSRF, uploads, privilege escalation and options, on a second set of CVEs.
- **Noise on popular plugins.** How many findings does the scanner print for the 200 most popular free plugins?

The recall and noise numbers published with each release are measured this way.

## How recall is measured

The CVE snapshot is in `data/cves.json`. It holds CVEs from 2023 to 2025 that the NVD links to a file and a line in the plugin's Trac repository. That gives the vulnerable file and line for each CVE.

For each plugin version the script:

1. Downloads the vulnerable version from wordpress.org.
2. Scans it.
3. Checks whether the scanner reported a finding of the matching class (SQL injection, XSS, PHP object injection, file inclusion, missing authorization).

The unit is a unique (CVE, plugin, version) pair. Two results are counted:

- **near.** A finding of the matching class within 25 lines of the CVE line, in the same file.
- **file.** A finding of the matching class anywhere in that file.

CSRF and CVEs outside these classes are skipped. Stored XSS is the largest class in the NVD and the hardest for a static scanner, so only its first 80 entries are used. This keeps it from drowning the other classes.

## How recall is measured for the 0.6.0 classes

The main set has few CVEs of the classes that the five `--extended` rules of 0.6.0 look for: file paths, SSRF, uploads, privilege escalation and options. A second set covers them. It is in `data/cves-extra.json`: 326 CVE entries in 284 plugin versions. `fetch-cves-extra.mjs` builds it from the NVD the same way as the main set. The measured classes are file upload, file read, file delete, SSRF, privilege escalation, authentication bypass, option update and remote code execution. They give 302 unique pairs. Open redirects and other classes are skipped. One version (`liquid-chatgpt` 1.0.1) no longer downloads, so the measurement covers 301 pairs.

`recall-extra.mjs` scans each version once with `--extended`. It counts near and file hits as above, and it counts them twice:

- **Before.** Only the rules that existed before the new family count. That is `wp.rce.dynamic` for remote code execution, and the rules for missing authorization (`wp.auth.unprotected_action`, `wp.rest.no_permission_callback`) for privilege escalation and authentication bypass.
- **After.** The new rules count as well. File upload adds the upload and path rules. File read and file delete add the path rule. SSRF adds the SSRF rule. Privilege escalation adds the account and option rules. Authentication bypass adds the account rule. Option update adds the option rule.

The mapping from the CVE class to the rules is written at the top of the script. It was fixed before the first measurement. For five of the eight classes there was no rule before, so their "before" column is zero by construction. The comparison says something only for the other three.

## How noise is measured

The script scans the plugins listed in `data/popular.json`. That is a frozen list of the 200 most popular free plugins on 2026-10-19. A frozen list makes two scanner versions comparable. Pass `--live` to fetch the current list instead.

It prints the median and the 90th percentile of findings per plugin, the number of plugins without findings, and the count per rule. The median must stay low. Today it is 1. Pass `--extended` to count the findings of the extended rules as well.

Two versions on the frozen list no longer download. On 2026-10-19 wordpress.org answers 404 for `duplicate-page` 4.5.9 and `wp-file-manager` 8.0.6. A run from scratch therefore scans 198 plugins (48 977 PHP files). The numbers for 0.5.0 and 0.6.0 below come from such a run. The 0.5.0 release notes give 580 findings and 97 plugins without a finding, which is the same run on all 200 versions as they were available then. The median (1) and the 90th percentile (6) are the same in both.

## Latest numbers

Scanner 0.6.0 against 0.5.0. The main set has 475 pairs: 445 CVE ids in 465 plugin versions. Another 17 versions could not be downloaded and are left out. The five rules of 0.6.0 work only with `--extended`, so the default mode and the main set did not change.

| | 0.5.0 | 0.6.0 |
| --- | --- | --- |
| Default mode, near | 144 of 475 (30.3%) | 144 of 475 (30.3%) |
| Default mode, file | 188 of 475 (39.6%) | 188 of 475 (39.6%) |
| `--extended`, near | 162 of 475 (34.1%) | 162 of 475 (34.1%) |
| `--extended`, file | 214 of 475 (45.1%) | 214 of 475 (45.1%) |
| Findings on 198 popular plugins | 579 | 579 |
| Median findings per plugin | 1 | 1 |
| 90th percentile | 6 | 6 |
| Plugins without findings | 96 | 96 |

Near hits by class, default mode and `--extended`. The classes are the same in 0.5.0 and 0.6.0:

| Class | Pairs | Default mode | `--extended` |
| --- | --- | --- | --- |
| SQL injection | 98 | 24 | 42 |
| Reflected XSS | 183 | 74 | 74 |
| Stored XSS | 85 | 21 | 21 |
| Missing authorization | 54 | 12 | 12 |
| File inclusion | 30 | 9 | 9 |
| PHP object injection | 25 | 4 | 4 |

With `--extended` on the 198 popular plugins, 0.6.0 gives 871 findings. 127 plugins have a finding and 71 do not. The median is 1 and the 90th percentile is 11. The five new rules give 43 of those findings in 19 plugins, and all of them are heuristics: 24 for file paths in 8 plugins, 3 for SSRF in 3, 10 for option names in 7, 6 for privilege escalation in 3 and none for uploads. The older extended rule `wp.sqli.param_unprepared` gives 249 findings in 50 plugins.

Second set, 301 pairs, `--extended`. Near hits without and with the new rules:

| Class | Pairs | Before | After |
| --- | --- | --- | --- |
| File upload | 84 | 0 | 13 |
| File read | 22 | 0 | 2 |
| File delete | 27 | 0 | 6 |
| Remote code execution | 29 | 5 | 5 |
| Authentication bypass | 40 | 2 | 8 |
| SSRF | 23 | 0 | 8 |
| Privilege escalation | 70 | 5 | 15 |
| Option update | 6 | 0 | 1 |
| All | 301 | 12 (4.0%) | 58 (19.3%) |

In the same set the file hits go from 29 (9.6%) to 87 (28.9%). The version that no longer downloads is left out of the table.

## What these numbers do not say

- There is no false-positive rate. A finding near a CVE line can be a different bug of the same class. A finding on a popular plugin can be real or not. Nobody has triaged all of them.
- Part of the gain is heuristic findings. The default mode reports firm findings and heuristics together.
- Three authorization pairs from 0.4.0 are no longer near hits in 0.5.0. The rule now reports at the handler definition, not at the `add_action` line. For these three, the finding moved out of the 25-line window. They are CVE-2025-5304 (project-notebooks 1.1.3), CVE-2025-13403 (employee-spotlight 5.1.3) and CVE-2025-14366 (eyewear-prescription-form 6.0.1).
- The 25-line window is a choice. A correct finding 30 lines from the CVE line counts as file, not near.
- Reflected and stored XSS make up most of the set. Most of those bugs need the data flow across files, which the scanner does not follow. That is why the XSS rows barely move.
- The sample covers only CVEs that link to a Trac line. It is not a random sample of all plugin bugs.
- The second set was visible while the five rules of 0.6.0 were tuned. The mapping from the CVE class to the rules was fixed before the first measurement, but the rules were adjusted afterwards to fit what the set showed. A blind test on new CVEs is still to do.
- For five of the eight classes of the second set the "before" column is zero by construction, because no rule existed. Only remote code execution, authentication bypass and privilege escalation compare old rules with new ones.
- The precision of the new rules was judged by reading their findings by hand: 43 on 252 plugins and themes from a local disk (42 151 PHP files) and 43 on the 198 popular plugins. That is a review, not a rate. Some of the findings that remain are by design, for example an administrator tool that writes files on purpose.
- The new rules still raise false alarms in a few known cases. A dispatcher checks the capability once and then calls handlers from a table. A capability sits in a constant or a property that another file defines. A REST route validates its arguments in the route definition. A container key is checked before it is stored. A gate sits in another file.
- One pair of the second set is missed because of a limit of the upload rule: CVE-2023-6827 (essential-real-estate 4.3.5). The rule counts an extension check on zip entries after the save, followed by a delete, as validation.
- A firm finding of a new rule fails the build under `--extended` at the default `--fail-on high`. All 43 findings on the popular plugins are heuristics, so they only warn.

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
node benchmark/recall.mjs --lib dist/index.js --out benchmark/results/x-recall.json [--extended] [--window 25] [--max 1000]
node benchmark/recall-extra.mjs --lib dist/index.js --out benchmark/results/x-recall-extra.json [--window 25]
node benchmark/noise.mjs --lib dist/index.js --out benchmark/results/x-noise.json [--extended] [--live]
node benchmark/fetch-cves.mjs --from 2023 --to 2025
node benchmark/fetch-cves-extra.mjs --from 2023 --to 2025
```

`fetch-cves.mjs` and `fetch-cves-extra.mjs` refresh the CVE snapshots from the NVD. The NVD limits the request rate, so each takes about an hour. The snapshots in the repository are enough to reproduce the numbers above.

## Safety

The plugin archives are untrusted code. The scripts only download, unpack and parse them. They never run anything from them, and they unpack into `benchmark/.cache`, which is git-ignored.
