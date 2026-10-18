# WPCoderScan

[![npm](https://img.shields.io/npm/v/wpcoderscan.svg)](https://www.npmjs.com/package/wpcoderscan)

Skaner bezpieczeństwa kodu WordPress i PHP. Wykrywa podatności w kodzie wtyczek, motywów i integracji, zanim trafią na produkcję. Narzędzie dla deweloperów, vendorów i agencji, na czasy kodu generowanego przez AI.

Status: wczesny etap (v0.3.2). Architektura wzorowana na skanerze AgentShield (MIT), kod w całości własny, z warstwą reguł PHP i WordPress. Szczegóły atrybucji w pliku `NOTICE`.

## Szybki start

Wymagany Node.js 18 lub nowszy. Skaner nie uruchamia kodu PHP. Czyta i parsuje pliki, więc można go bezpiecznie puścić na cudzym kodzie.

```bash
npx wpcoderscan ./sciezka-do-wtyczki
```

Możesz też zainstalować go globalnie:

```bash
npm i -g wpcoderscan
wpcoderscan ./sciezka-do-wtyczki
```

Wersję sprawdzisz przez `--version`. Ten sam skaner uruchomisz też prosto z GitHuba, bez pakietu npm:

```bash
npx github:wpcoder23/wpcoderscan ./sciezka-do-wtyczki
```

albo z lokalnej kopii repozytorium:

```bash
git clone https://github.com/wpcoder23/wpcoderscan.git
cd wpcoderscan
npm install
node dist/cli.js ./sciezka-do-wtyczki --json
```

## Co wykrywa

Skaner pokrywa osiem klas podatności. Reguły śledzą dane użytkownika w obrębie jednej funkcji. Zmienna przypisana z `$_GET` jest skażona, a po rzutowaniu na liczbę, `absint`, `esc_sql` czy `escapeshellarg` już nie.

Za dane od użytkownika skaner uznaje:

- superglobale (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, `$_FILES`),
- `filter_input`, `filter_input_array` bez filtra czyszczącego oraz `php://input`,
- obiekt żądania REST (`$request->get_param()`, `$request['x']`), jako heurystykę, bo trasa mogła zwalidować argumenty,
- atrybuty shortcode (`$atts` oraz klucze z `shortcode_atts`), jako źródło zapisanego XSS,
- `add_query_arg` i `remove_query_arg` bez podanego adresu, w regule XSS.

Elementy tablicy są śledzone po literalnym kluczu, więc `$a['x']` z `$_GET` nie skazi `$a['y']`.

Zmienna sprawdzona przed użyciem przestaje być skażona. Skaner uznaje za sprawdzenie `in_array`, `array_key_exists`, `isset` na tablicy z kluczem ze zmiennej, `ctype_*`, `is_numeric`, zakotwiczone wyrażenie regularne i porównanie z literałem. Działa to w ciele `if`, w gałęzi `else` po negacji oraz po wczesnym wyjściu (`return`, `die`, `wp_die`). Skaner nie ocenia, czy lista dozwolonych wartości jest poprawna.

- SQL injection: zapytania `$wpdb` budowane bez `prepare` z danych użytkownika. Superglobal wprost w zapytaniu jest pewny, zmienna zasilona superglobalem to heurystyka.
- REST: trasa bez `permission_callback` (pewne). `__return_true` na trasie zmieniającej dane (heurystyka). Trasy tylko do odczytu pomijamy.
- RCE: `eval`, `include` i `require` ze ścieżką od użytkownika, backticki, rodzina `exec` i `shell_exec`. Dane z superglobala wprost są pewne, przez zmienną to heurystyka.
- Deserializacja: `unserialize` i `maybe_unserialize` na superglobalu (pewne).
- Opcje: `register_setting` bez `sanitize_callback` (pewne).
- Sekrety: klucze dostawców (AWS, Stripe, GitHub, Slack, SendGrid, klucz prywatny z treścią) jako pewne. Klucz API Google i wykrycie po nazwie zmiennej jako heurystyka, bo klucze do map bywają publiczne z założenia.
- XSS: dane użytkownika w `echo`, `print`, `printf`, `die`, `wp_die` oraz w wartości zwracanej przez shortcode, bez `esc_*`, `wp_kses`, `sanitize_*` ani rzutowania (heurystyka).
- Nonce i uprawnienia: uchwyty `admin_post_*` i `wp_ajax_*`, które zmieniają stan bez weryfikacji nonce albo bez `current_user_can` (heurystyka). Uchwytem może być funkcja, domknięcie albo metoda klasy z tego samego pliku. Brak uprawnień przy obecnym nonce to poziom średni, a brak obu zabezpieczeń to wysoki.

Tryb rozszerzony (`--extended`) dodaje regułę `wp.sqli.param_unprepared`: parametr funkcji wklejony do zapytania `$wpdb` bez `prepare`. Skaner nie widzi wywołujących, więc to ostrzeżenie średniego poziomu, domyślnie wyłączone. Tak wygląda wiele historycznych podatności SQL injection, a zarazem sporo bezpiecznego kodu, dlatego trzeba o nią poprosić.

Pełny opis każdej reguły z przykładami podatnego i poprawnego kodu jest w [docs/reguly.md](docs/reguly.md).

Każde znalezisko dostaje poziom (krytyczny, wysoki, średni, niski), poziom pewności, miejsce w kodzie i wskazówkę naprawy. Wyniki mapujemy na OWASP ASVS i CWE.

Skaner pomija katalogi `vendor`, `vendor-prefixed`, `node_modules`, `.git`, `dist` i `build`.

## Pewność i bramka CI

Każde znalezisko ma poziom pewności. Znaleziska **pewne** (firm) są strukturalnie jednoznaczne i łamią build. Znaleziska **heurystyczne** mogą dać fałszywy alarm, więc domyślnie tylko ostrzegają i nie wywalają CI. Flaga `--strict` sprawia, że do kodu wyjścia liczą się też heurystyki.

`wpcoderscan` zwraca kod `1`, gdy znajdzie podatność o poziomie wskazanym w `--fail-on` (domyślnie `high`) lub cięższym, z uwzględnieniem powyższej zasady pewności. Dzięki temu wpina się w CI jako bramka. Kod `2` oznacza błąd działania skanera.

## Ograniczenia

Analiza danych działa w obrębie jednej funkcji i jednego pliku. Nie śledzi przepływu między funkcjami ani plikami i nie zna własnych funkcji czyszczących projektu. Callbacki rejestrowane w innym pliku niż ich definicja zostają nierozwiązane. Brak alarmu nie dowodzi, że kod jest bezpieczny. Skaner nie zastępuje przeglądu kodu ani testu penetracyjnego.

## Podpowiedzi napraw

Dla dwóch reguł skaner umie podać gotową zmianę kodu: XSS w `echo` i `print` oraz `unserialize` na danych od użytkownika. Skaner niczego nie zapisuje w twoich plikach. Pokazuje zmianę albo zapisuje ją jako łatkę, a decyzja należy do ciebie.

- `--suggest` pokazuje przy znalezisku, co zmienić, jako linie przed i po.
- `--patch naprawy.patch` zapisuje wszystkie pełne podpowiedzi jako łatkę. Uruchom skan z katalogu głównego repozytorium, a potem: `git apply --check naprawy.patch && git apply naprawy.patch`.
- JSON zawiera pole `patch` przy znalezisku, a SARIF zawiera pole `fixes`.

Skaner dobiera funkcję ucieczki do miejsca w HTML. W treści strony to `esc_html()`, w atrybucie w cudzysłowie `esc_attr()`, a w całym adresie `href` albo `src` `esc_url()`. Przy `unserialize` dopisuje `allowed_classes => false`. Zachowuje styl pliku: spacje w nawiasach, `array()` albo `[]`, końce linii CRLF.

Każdą podpowiedź skaner sprawdza przed pokazaniem. Nakłada zmianę w pamięci, parsuje kod ponownie, skanuje go jeszcze raz i odrzuca podpowiedź, gdy znalezisko nie znika albo pojawia się nowe. Odrzuca ją także, gdy plik ma błędy składni.

Podpowiedzi nie dostaje nic, co wymaga decyzji o kontekście: skrypty, style, atrybuty zdarzeń, wartości bez cudzysłowu i adres, w którym dane stoją na początku, a dalej jest ciąg dalszy. Podpowiedź oznaczona jako "do decyzji" pojawia się tylko w `--suggest`. Nie trafia do łatki. Tak jest, gdy kontekstu HTML nie widać w kodzie, a skaner proponuje wtedy `esc_html()`.

Wstrzyknięcia SQL, RCE, brak kontroli dostępu i zaszyte sekrety skaner celowo nie naprawia sam, bo poprawna zmiana zależy od projektu.

## Formaty wyjścia

- Terminal (domyślnie), czytelny raport z oceną.
- `--json`, do dalszego przetwarzania.
- `--sarif`, format SARIF 2.1.0 do zakładki Security w GitHub.
- `--diff <ref>`, skan tylko plików PHP zmienionych wobec ref gita (szybki skan dla pull requestów).
- `--suggest` i `--patch <plik>`, podpowiedzi napraw (opisane wyżej).
- `--extended`, dodatkowe reguły o niższej precyzji (opisane wyżej).

## GitHub Action

Skan na każdym push i pull request, z wynikami w zakładce Security. Akcja buduje skaner ze źródeł repozytorium w wersji wskazanej tagiem, więc nie wymaga pakietu npm. Gotowy przykład jest w `examples/github-workflow.yml`. Pokaz na żywo, z wynikami w zakładce Security: [wpcoder23/wpcoderscan-demo](https://github.com/wpcoder23/wpcoderscan-demo). Minimalny workflow:

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: wpcoder23/wpcoderscan@v0.3.2
        with:
          path: .
          fail-on: high
          # extended: 'true'   # dodatkowe reguły o niższej precyzji
```

## Licencja

Apache-2.0. Rdzeń jest otwarty. Adaptowane fragmenty z projektów MIT zachowują swoją notę licencyjną. Zobacz pliki `LICENSE` i `NOTICE`.
