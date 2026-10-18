# WPCoderScaner

Skaner bezpieczeństwa kodu WordPress i PHP. Wykrywa podatności w kodzie wtyczek, motywów i integracji, zanim trafią na produkcję. Narzędzie dla deweloperów, vendorów i agencji, na czasy kodu generowanego przez AI.

Status: wczesny etap budowy (v0.1.0). Rdzeń oparty na silniku AgentShield (MIT), z własną warstwą reguł PHP i WordPress. Szczegóły atrybucji w pliku `NOTICE`.

## Szybki start

```bash
npx wpcoderscaner ./sciezka-do-wtyczki
```

albo po instalacji, krótszą komendą `wpcs`:

```bash
wpcs ./sciezka-do-wtyczki --json
```

## Co wykrywa

Pierwsza wersja (w budowie) skupia się na najczęstszych i najgroźniejszych klasach podatności we wtyczkach WordPress:

- SQL injection: zapytania `$wpdb` budowane bez `prepare` z danych dynamicznych.
- Kolejne reguły dokładane sukcesywnie: XSS i brak escapingu, brak nonce i CSRF, brak sprawdzenia uprawnień, REST route bez `permission_callback`, niebezpieczny upload, `unserialize` na danych użytkownika, RCE, SSRF, sekrety w kodzie.

Każde znalezisko dostaje poziom (krytyczny, wysoki, średni, niski), miejsce w kodzie i wskazówkę naprawy. Wyniki mapujemy na OWASP ASVS.

## Formaty wyjścia

- Terminal (domyślnie), czytelny raport z oceną.
- `--json`, do dalszego przetwarzania.
- SARIF, do zakładki Security w GitHub (w budowie).

## Kod wyjścia

`wpcs` zwraca kod `1`, gdy znajdzie podatność o poziomie wskazanym w `--fail-on` (domyślnie `high`) lub cięższym. Dzięki temu wpina się w CI jako bramka.

## Licencja

Apache-2.0. Rdzeń jest otwarty. Adaptowane fragmenty z projektów MIT zachowują swoją notę licencyjną. Zobacz pliki `LICENSE` i `NOTICE`.
