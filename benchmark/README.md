# Benchmark

These scripts measure two things. You can rerun both.

- **Recall on known vulnerabilities.** How many historical WordPress plugin CVEs does the scanner report?
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

## How noise is measured

The script scans the plugins listed in `data/popular.json`. That is a frozen list of the 200 most popular free plugins on 2026-10-19. A frozen list makes two scanner versions comparable. Pass `--live` to fetch the current list instead.

It prints the median and the 90th percentile of findings per plugin, the number of plugins without findings, and the count per rule. The median must stay low. Today it is 1.

## Latest numbers

Scanner 0.5.0 against 0.4.0. The set has 475 pairs: 445 CVE ids in 465 plugin versions. Another 17 versions could not be downloaded and are left out.

| | 0.4.0 | 0.5.0 |
| --- | --- | --- |
| Default mode, near | 117 of 475 (24.6%) | 144 of 475 (30.3%) |
| Default mode, file | 157 of 475 (33.1%) | 188 of 475 (39.6%) |
| `--extended`, near | 139 of 475 (29.3%) | 162 of 475 (34.1%) |
| `--extended`, file | 191 of 475 (40.2%) | 214 of 475 (45.1%) |
| Findings on 200 popular plugins | 580 | 580 |
| Median findings per plugin | 1 | 1 |
| 90th percentile | 6 | 6 |
| Plugins without findings | 97 | 97 |

Near hits by class, default mode and `--extended`:

| Class | Pairs | 0.4.0 | 0.5.0 | 0.4.0 `--extended` | 0.5.0 `--extended` |
| --- | --- | --- | --- | --- | --- |
| SQL injection | 98 | 9 | 24 | 31 | 42 |
| Reflected XSS | 183 | 74 | 74 | 74 | 74 |
| Stored XSS | 85 | 19 | 21 | 19 | 21 |
| Missing authorization | 54 | 10 | 12 | 10 | 12 |
| File inclusion | 30 | 3 | 9 | 3 | 9 |
| PHP object injection | 25 | 2 | 4 | 2 | 4 |

## What these numbers do not say

- There is no false-positive rate. A finding near a CVE line can be a different bug of the same class. A finding on a popular plugin can be real or not. Nobody has triaged all of them.
- Part of the gain is heuristic findings. The default mode reports firm findings and heuristics together.
- Three authorization pairs from 0.4.0 are no longer near hits in 0.5.0. The rule now reports at the handler definition, not at the `add_action` line. For these three, the finding moved out of the 25-line window. They are CVE-2025-5304 (project-notebooks 1.1.3), CVE-2025-13403 (employee-spotlight 5.1.3) and CVE-2025-14366 (eyewear-prescription-form 6.0.1).
- The 25-line window is a choice. A correct finding 30 lines from the CVE line counts as file, not near.
- Reflected and stored XSS make up most of the set. Most of those bugs need the data flow across files, which the scanner does not follow. That is why the XSS rows barely move.
- The sample covers only CVEs that link to a Trac line. It is not a random sample of all plugin bugs.

## How to run

Node 18 or newer, and `tar` or `unzip` on the PATH. From the repository root:

```
npm ci
npm run build
node benchmark/run.mjs --label current
```

The first run downloads about 700 archives into `benchmark/.cache`. Later runs reuse them. The run takes a few minutes.

To compare with an older release, build that release in a separate clone and point `--lib` at its `dist/index.js`:

```
node benchmark/run.mjs --lib /path/to/old/dist/index.js --label base
node benchmark/compare.mjs --base base --cand current --new
```

`compare.mjs` prints the change per class, the pairs that stopped matching, the change in noise per rule and, with `--new`, the findings that did not exist before. Read the new findings. They show where precision may have dropped.

Single parts, if you need them:

```
node benchmark/recall.mjs --lib dist/index.js --out benchmark/results/x-recall.json [--extended] [--window 25] [--max 1000]
node benchmark/noise.mjs --lib dist/index.js --out benchmark/results/x-noise.json [--extended] [--live]
node benchmark/fetch-cves.mjs --from 2023 --to 2025
```

`fetch-cves.mjs` refreshes the CVE snapshot from the NVD. The NVD limits the request rate, so it takes about an hour. The snapshot in the repository is enough to reproduce the numbers above.

## Safety

The plugin archives are untrusted code. The scripts only download, unpack and parse them. They never run anything from them, and they unpack into `benchmark/.cache`, which is git-ignored.
