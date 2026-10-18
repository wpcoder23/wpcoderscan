# WPCoderScaner

Skaner bezpieczeństwa kodu WordPress i PHP. Wykrywa podatności w kodzie wtyczek, motywów i integracji, zanim trafią na produkcję. Narzędzie dla deweloperów, vendorów i agencji, na czasy kodu generowanego przez AI.

Status: wczesny etap budowy (v0.1.0). Architektura wzorowana na skanerze AgentShield (MIT), kod w całości własny, z warstwą reguł PHP i WordPress. Szczegóły atrybucji w pliku `NOTICE`.

## Szybki start

```bash
npx wpcoderscaner ./sciezka-do-wtyczki
```

albo po instalacji, krótszą komendą `wpcs`:

```bash
wpcs ./sciezka-do-wtyczki --json
```

## Co wykrywa

Wersja v1 pokrywa osiem klas podatności, z priorytetem dla reguł strukturalnych o wysokiej precyzji:

- SQL injection: zapytania `$wpdb` budowane bez `prepare` z danych dynamicznych (pewne).
- REST: rejestracja trasy bez `permission_callback` albo z `__return_true` (pewne).
- RCE: `eval`, dynamiczny `include` i `require`, backticki, rodzina `exec` i `shell_exec` na danych dynamicznych (pewne).
- Deserializacja: `unserialize` i `maybe_unserialize` na superglobalu (pewne).
- Opcje: `register_setting` bez `sanitize_callback` (pewne).
- Sekrety: klucze dostawców (AWS, Stripe, GitHub, Google, Slack, SendGrid, klucz prywatny) jako pewne, wykrycie po nazwie zmiennej jako heurystyka.
- XSS: `echo` albo `print` superglobala bez `esc_*`, `wp_kses`, `sanitize_*` ani rzutowania (heurystyka).
- Nonce i uprawnienia: uchwyty `admin_post_*` i `wp_ajax_*` bez weryfikacji nonce albo bez `current_user_can` (heurystyka).

Każde znalezisko dostaje poziom (krytyczny, wysoki, średni, niski), poziom pewności, miejsce w kodzie i wskazówkę naprawy. Wyniki mapujemy na OWASP ASVS i CWE.

## Pewność i bramka CI

Każda reguła ma poziom pewności. Znaleziska **pewne** (firm) są strukturalnie jednoznaczne i łamią build. Znaleziska **heurystyczne** mogą dać fałszywy alarm, więc domyślnie tylko ostrzegają i nie wywalają CI. Flaga `--strict` sprawia, że do kodu wyjścia liczą się też heurystyki.

`wpcs` zwraca kod `1`, gdy znajdzie podatność o poziomie wskazanym w `--fail-on` (domyślnie `high`) lub cięższym, z uwzględnieniem powyższej zasady pewności. Dzięki temu wpina się w CI jako bramka.

## Formaty wyjścia

- Terminal (domyślnie), czytelny raport z oceną.
- `--json`, do dalszego przetwarzania.
- `--sarif`, format SARIF 2.1.0 do zakładki Security w GitHub.

## GitHub Action

Skan na każdym push i pull request, z wynikami w zakładce Security. Gotowy przykład jest w `examples/github-workflow.yml`. Minimalny workflow:

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npx --yes wpcoderscaner . --sarif --fail-on high > wpcoderscaner.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: wpcoderscaner.sarif
```

Repozytorium zawiera też akcję composite (`action.yml`) do publikacji w Marketplace.

## Licencja

Apache-2.0. Rdzeń jest otwarty. Adaptowane fragmenty z projektów MIT zachowują swoją notę licencyjną. Zobacz pliki `LICENSE` i `NOTICE`.
