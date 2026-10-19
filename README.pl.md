# WPCoderScan

[![npm](https://img.shields.io/npm/v/wpcoderscan.svg)](https://www.npmjs.com/package/wpcoderscan)
[![CI](https://github.com/wpcoder23/wpcoderscan/actions/workflows/ci.yml/badge.svg)](https://github.com/wpcoder23/wpcoderscan/actions/workflows/ci.yml)

Skaner bezpieczeństwa kodu WordPress i PHP. Wykrywa podatności w kodzie wtyczek, motywów i integracji, zanim trafią na produkcję. Narzędzie dla deweloperów, vendorów i agencji, na czasy kodu generowanego przez AI.

[English](README.md) | Polski

To wczesny etap (v0.8.1). Architektura i część rozwiązań (raport, ocena, skanowanie z linii poleceń) pochodzą z projektów ECC i AgentShield na licencji MIT. Reguły PHP i WordPress, kolektor plików, integracja parsera i mapowanie na OWASP ASVS i CWE są oryginalne. Szczegóły atrybucji w pliku `NOTICE`.

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

Skaner pokrywa osiem klas podatności, a z flagą `--extended` jeszcze pięć. Reguły śledzą dane użytkownika w obrębie funkcji i przez wywołania między funkcjami z tego samego pliku. Zmienna przypisana z `$_GET` jest skażona, a po rzutowaniu na liczbę, `absint` czy `escapeshellarg` już nie. `esc_sql` zdejmuje skażenie tylko dla wartości w cudzysłowie zapytania.

Za dane od użytkownika skaner uznaje:

- superglobale (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, `$_FILES`),
- `filter_input`, `filter_input_array` bez filtra czyszczącego oraz `php://input`,
- obiekt żądania REST (`$request->get_param()`, `$request['x']`), jako heurystykę, bo trasa mogła zwalidować argumenty,
- atrybuty shortcode (`$atts` oraz klucze z `shortcode_atts`), jako źródło zapisanego XSS,
- `add_query_arg` i `remove_query_arg` bez podanego adresu, w regule XSS.

Elementy tablicy są śledzone po literalnym kluczu, więc `$a['x']` z `$_GET` nie skazi `$a['y']`.

Zmienna sprawdzona przed użyciem przestaje być skażona. Skaner uznaje za sprawdzenie `in_array`, `array_key_exists`, `isset` na tablicy z kluczem ze zmiennej, `ctype_*`, `is_numeric`, zakotwiczone wyrażenie regularne, wyrażenie regularne odrzucające każdy znak spoza zbioru, porównanie z literałem oraz walidator o nazwie w rodzaju `is_valid_*` albo `validate_*`. Działa to w ciele `if`, w gałęziach warunku trójargumentowego, w gałęzi `else` po negacji oraz po wczesnym wyjściu (`return`, `die`, `wp_die`). Skaner nie ocenia, czy lista dozwolonych wartości jest poprawna.

- SQL injection: zapytania `$wpdb` budowane bez `prepare` z danych użytkownika. Superglobal wprost w zapytaniu jest pewny, zmienna zasilona superglobalem to heurystyka. `prepare` chroni tylko podane mu wartości, więc dane wklejone w tekst zapytania są nadal zgłaszane. Zgłaszamy też `esc_sql` użyte poza cudzysłowem (liczba, kolumna, `ORDER BY`).
- REST: trasa bez `permission_callback` (pewne). `__return_true` na trasie zmieniającej dane (heurystyka). Trasy tylko do odczytu pomijamy.
- RCE: `eval`, `include` i `require` ze ścieżką od użytkownika, funkcje ładujące szablon po nazwie od użytkownika (`get_template_part`, `load_template`), backticki, rodzina `exec` i `shell_exec`. Dane z superglobala wprost są pewne, przez zmienną to heurystyka.
- Deserializacja: `unserialize` i `maybe_unserialize` na superglobalu (pewne) albo na zmiennej zasilonej danymi użytkownika (heurystyka).
- Opcje: `register_setting` bez `sanitize_callback` (pewne).
- Sekrety: klucze dostawców (AWS, Stripe, GitHub, Slack, SendGrid, klucz prywatny z treścią) jako pewne. Klucz API Google i wykrycie po nazwie zmiennej jako heurystyka, bo klucze do map bywają publiczne z założenia.
- XSS: dane użytkownika w `echo`, `print`, `printf`, `die`, `wp_die` oraz w wartości zwracanej przez shortcode, bez `esc_*`, `wp_kses`, `sanitize_*` ani rzutowania (heurystyka).
- Nonce i uprawnienia: uchwyty `admin_post_*` i `wp_ajax_*`, które zmieniają stan bez weryfikacji nonce albo bez `current_user_can` (heurystyka). Uchwytem może być funkcja, domknięcie albo metoda klasy z tego samego pliku. Brak uprawnień przy obecnym nonce to poziom średni, a brak obu zabezpieczeń to wysoki.

Tryb rozszerzony (`--extended`) dodaje sześć reguł. Są domyślnie wyłączone, bo łapią prawdziwe błędy, a zarazem sporo bezpiecznego kodu, dlatego trzeba o nie poprosić.

- `wp.sqli.param_unprepared`: parametr funkcji wklejony do zapytania `$wpdb` bez `prepare`. Skaner nie widzi wywołujących z innych plików, więc to ostrzeżenie średniego poziomu.
- `wp.file.path_traversal`: plik czytany, zapisywany albo usuwany pod ścieżką od użytkownika (`file_get_contents`, `unlink`, `file_put_contents`, `copy`, `$wp_filesystem` i inne). Ścieżka zredukowana przez `basename` albo sprawdzona przez `realpath` nie jest zgłaszana.
- `wp.http.ssrf`: żądanie HTTP pod adres od użytkownika (`wp_remote_get`, `curl_init`, `fsockopen`). Dane użytkownika doklejone za ustalonym hostem nie są zgłaszane, a `wp_safe_remote_*` zostaje poza regułą.
- `wp.upload.unrestricted`: wysłany plik zapisany pod nazwą od klienta bez sprawdzenia typu albo `wp_handle_upload` z wyłączonym `test_type`.
- `wp.privilege.escalation`: rola, logowanie albo uprawnienia konta wzięte z żądania (`wp_insert_user`, `set_role`, `update_user_meta`, `wp_set_auth_cookie`).
- `wp.option.arbitrary_update`: nazwa opcji wzięta od użytkownika (`update_option( $_POST['name'], ... )`).

Kod dostępny tylko dla administratora nie jest otwartymi drzwiami dla odwiedzającego. Reguły plików, żądań i wysyłania dają dla niego tylko wskazówkę o niskim poziomie, a reguły kont i opcji milczą. Skaner uznaje za bramkę sprawdzenie uprawnienia administratora, stronę menu albo trasę REST zarejestrowane z takim uprawnieniem, hook zarejestrowany tylko pod takim sprawdzeniem, funkcję uprawnień o nazwie sprawdzenia administratora i pomocnika, którego ten sam plik woła wyłącznie z kodu za taką bramką. Nonce nie jest bramką. Szczegóły są w [docs/reguly.md](docs/reguly.md#bramka-administratora).

Pełny opis każdej reguły z przykładami podatnego i poprawnego kodu jest w [docs/reguly.md](docs/reguly.md) (po angielsku: [docs/rules.md](docs/rules.md)).

Każde znalezisko dostaje poziom (krytyczny, wysoki, średni, niski), poziom pewności, miejsce w kodzie i wskazówkę naprawy. Wyniki mapujemy na OWASP ASVS i CWE.

Skaner pomija katalogi `vendor`, `vendor-prefixed`, `node_modules`, `.git`, `dist` i `build`.

## Pewność i bramka CI

Każde znalezisko ma poziom pewności. Znaleziska **pewne** (firm) są strukturalnie jednoznaczne i łamią build. Znaleziska **heurystyczne** mogą dać fałszywy alarm, więc domyślnie tylko ostrzegają i nie wywalają CI. Flaga `--strict` sprawia, że do kodu wyjścia liczą się też heurystyki.

`wpcoderscan` zwraca kod `1`, gdy znajdzie podatność o poziomie wskazanym w `--fail-on` (domyślnie `high`) lub cięższym, z uwzględnieniem powyższej zasady pewności. Dzięki temu wpina się w CI jako bramka. Kod `2` oznacza błąd działania skanera albo błędny argument.

## Język

Wyjście jest domyślnie po angielsku. Polskie komunikaty włączysz flagą `--lang pl` albo zmienną środowiskową `WPCODERSCAN_LANG=pl`. Flaga ma pierwszeństwo przed zmienną. Język dotyczy raportu w terminalu, komunikatów w JSON i SARIF, podpowiedzi napraw oraz błędów. Identyfikatory reguł i klucze JSON się nie zmieniają.

```bash
npx wpcoderscan ./sciezka-do-wtyczki --lang pl
```

## Wyniki pomiarów

Skaner mierzymy na znanych podatnościach i na popularnych wtyczkach. Główny zbiór ma 475 par: zgłoszenie CVE i podatna wersja wtyczki, lata 2023-2025. Reguły powstawały, gdy ten zbiór był widoczny, więc pokazuje on, jak dobrze pasują do znanych błędów.

- Tryb domyślny zgłasza znalezisko właściwej klasy w odległości do 25 linii od linii z CVE w 173 z 475 przypadków (36,4%). Z `--extended` jest to 191 z 475 (40,2%). Wersja 0.8.1 daje te same liczby, bo tylko usuwa znaleziska.
- Test ślepy używa 618 par z CVE opublikowanych w 2026 roku. Żadna reguła nie powstawała pod nie. Wersja 0.8.0 zgłasza właściwą klasę w odległości do 25 linii od linii z CVE w trybie domyślnym w 80 przypadkach (12,9%), a z `--extended` w 129 (20,9%). Wersja 0.7.0 ma na tym samym zbiorze 73 (11,8%) i 121 (19,6%). Wersji 0.8.1 na tym zbiorze nie uruchamiano. Takich liczb należy się spodziewać na nowym kodzie. Zbiór widoczny pochlebia skanerowi.
- Drugi zbiór, 301 par, obejmuje klasy pięciu reguł, które `--extended` dostało w 0.6.0. Z `--extended` skaner zgłasza właściwą klasę w odległości do 25 linii od linii z CVE w 62 z 301 przypadków (20,6%). Bez nowych reguł ten sam skan zgłasza 14 (4,7%). Reguły strojono, gdy ten zbiór był widoczny, więc to nie jest test ślepy. Te same klasy w CVE z 2026 roku, 440 par, dają 46 (10,5%) z nowymi regułami i 13 (3,0%) bez nich.
- Na 200 najpopularniejszych darmowych wtyczkach z wordpress.org, z których 198 da się jeszcze pobrać (49 tysięcy plików PHP), 112 wtyczek nie ma żadnego znaleziska w trybie domyślnym. Mediana to zero znalezisk na wtyczkę, a tryb domyślny wypisuje 403 znaleziska (w 0.8.0 było ich 517). Z `--extended` mediana wynosi jeden, a pięć nowych reguł dodaje 52 znaleziska w 23 wtyczkach.

Wiele chybień to XSS, w którym dane przechodzą między plikami. Skaner śledzi wywołania tylko w obrębie pliku. Ręczny przegląd 517 znalezisk z 0.8.0 na popularnych wtyczkach wykazał około jednej czwartej fałszywych alarmów i około dwóch trzecich znalezisk trafnych, ale o niskim ryzyku, na przykład publiczny endpoint, który jest publiczny z założenia. Wersja 0.8.1 usuwa 111 z tych fałszywych alarmów. Według tego samego przeglądu 403 znaleziska, które zostają, to około 7% prawdziwych słabości, 85% znalezisk trafnych o niskim ryzyku i 8% fałszywych alarmów. Recenzent pisał też poprawki, więc czytaj to jako zliczenie tego, co wykazał przegląd. Metoda, liczby, dane i skrypty są w [benchmark/](benchmark/README.md). Możesz uruchomić pomiary ponownie.

## Ograniczenia

Analiza danych działa w obrębie pliku. Śledzi wywołania funkcji i metod z tego samego pliku, do sześciu poziomów. Nie śledzi przepływu między plikami i nie zna własnych funkcji czyszczących projektu. Callbacki rejestrowane w innym pliku niż ich definicja zostają nierozwiązane. Skaner wie, w której gałęzi `if`, `switch`, pętli albo `catch` leży zapis, ale nie ocenia warunków. Flaga wybierająca gałąź oraz wczesny `return` albo `exit` w gałęzi nie są rozumiane. Brak alarmu nie dowodzi, że kod jest bezpieczny. Skaner nie zastępuje przeglądu kodu ani testu penetracyjnego.

## Podpowiedzi napraw

Dla dwóch reguł skaner umie podać gotową zmianę kodu: XSS w `echo` i `print` oraz `unserialize` na danych od użytkownika. Skaner niczego nie zapisuje w twoich plikach. Pokazuje zmianę albo zapisuje ją jako łatkę, a decyzja należy do ciebie.

- `--suggest` pokazuje przy znalezisku, co zmienić, jako linie przed i po.
- `--patch naprawy.patch` zapisuje wszystkie pełne podpowiedzi jako łatkę. Uruchom skan z katalogu głównego repozytorium, a potem: `git apply --check naprawy.patch && git apply naprawy.patch`.
- JSON zawiera pole `patch` przy znalezisku, a SARIF zawiera pole `fixes`.

Skaner dobiera funkcję ucieczki do miejsca w HTML. W treści strony to `esc_html()`, w atrybucie w cudzysłowie `esc_attr()`, a w całym adresie `href` albo `src` `esc_url()`. Przy `unserialize` dopisuje `allowed_classes => false`. Zachowuje styl pliku: spacje w nawiasach, `array()` albo `[]`, końce linii CRLF.

Każdą podpowiedź skaner sprawdza przed pokazaniem. Nakłada zmianę w pamięci, parsuje kod ponownie, skanuje go jeszcze raz i odrzuca podpowiedź, gdy znalezisko nie znika albo pojawia się nowe. Odrzuca ją także, gdy plik ma błędy składni.

Podpowiedzi nie dostaje nic, co wymaga decyzji o kontekście: skrypty, style, atrybuty zdarzeń, wartości bez cudzysłowu i adres, w którym dane stoją na początku, a dalej jest ciąg dalszy. Podpowiedź oznaczona jako "do decyzji" pojawia się tylko w `--suggest`. Nie trafia do łatki. Tak jest, gdy kontekstu HTML nie widać w kodzie, a skaner proponuje wtedy `esc_html()`.

Wstrzyknięcia SQL, RCE, brak kontroli dostępu i zaszyte sekrety skaner celowo nie naprawia sam, bo poprawna zmiana zależy od projektu.

## Wdrożenie w istniejącym kodzie

Skaner, który pierwszego dnia zgłasza setki starych znalezisk, zostaje wyłączony. Trzy narzędzia pozwalają zacząć z czystą bramką i naprawiać stare znaleziska z czasem.

### Baseline

Zapisz dzisiejsze znaleziska raz. Od tej chwili skaner zgłasza, i łamie build, tylko na nowych znaleziskach.

```bash
npx wpcoderscan . --write-baseline .wpcoderscan-baseline.json
npx wpcoderscan . --baseline .wpcoderscan-baseline.json
```

Zatwierdź plik w repozytorium. Znalezisko dopasowujemy po regule, pliku, treści jego linii i numerze wśród identycznych linii. Numer linii nie gra roli, więc przenoszenie kodu nie przywraca starych znalezisk. Gdy naprawisz stare znalezisko, jego wpis staje się nieaktualny. Raport podaje, ile wpisów nie ma dopasowania, a `--write-baseline` odświeża plik.

`--write-baseline` zawsze skanuje od zera, zapisuje plik i kończy się kodem 0. Nie działa razem z `--diff`, bo baseline objąłby tylko zmienione pliki. Uruchamiaj każdy skan z tego samego katalogu, bo plik zapisuje ścieżki względem katalogu roboczego.

### Komentarze wyciszające

Oznacz znalezisko, które zostało przejrzane i zaakceptowane.

```php
// wpcoderscan-ignore wp.rce.dynamic -- nazwa szablonu pochodzi ze stałej listy
include $path;

$rows = $wpdb->get_results( $sql ); // wpcoderscan-ignore wp.sqli.unprepared -- $sql składa się z rzutowań

// wpcoderscan-ignore-file wp.secret.hardcoded -- publiczny klucz demonstracyjny
```

- Komentarz w osobnej linii obejmuje następną linię. Komentarz za kodem obejmuje własną linię. `wpcoderscan-ignore-file` obejmuje cały plik. Działają `//`, `#` i `/* */`.
- Identyfikator reguły jest wymagany. Kilka identyfikatorów oddziel przecinkami albo użyj `*`, na przykład `wp.xss.*`.
- Komentarz bez identyfikatora niczego nie wycisza i pojawia się jako ostrzeżenie. Tak samo identyfikator, który nie pasuje do żadnej reguły. Dzięki temu widać literówki.
- Tekst po ` -- ` to powód.
- Raport zawsze podaje, ile znalezisk wyciszyły komentarze. JSON wymienia je w polu `suppressed`, a SARIF niesie ich liczbę we właściwościach przebiegu. GitHub nie honoruje wyciszeń zapisanych w SARIF, więc wyciszonych znalezisk nie ma w wynikach SARIF.
- Przy audycie cudzego kodu dodaj `--no-ignore-comments`. Inaczej autor mógłby ukryć znaleziska komentarzem.

### Plik ustawień

`.wpcoderscan.json` w bieżącym katalogu zawiera te same opcje co flagi, więc zespół dzieli jedną konfigurację.

```json
{
  "failOn": "high",
  "strict": false,
  "extended": false,
  "lang": "pl",
  "exclude": ["tests/", "legacy/", "*.min.php"],
  "rules": { "wp.auth.unprotected_action": "off" },
  "baseline": ".wpcoderscan-baseline.json",
  "ignoreComments": true
}
```

- Flaga ma pierwszeństwo przed zmienną środowiskową, zmienna przed plikiem, a plik przed wartością domyślną.
- Skaner czyta plik tylko z bieżącego katalogu albo ze ścieżki podanej w `--config`. Nigdy nie czyta go ze skanowanego kodu, więc sprawdzana wtyczka nie wyłączy skanerowi reguł. `--no-config` pomija plik.
- `exclude` przyjmuje proste wzorce ścieżek względem pliku ustawień: `*`, `**` i `?`. Nazwa bez ukośnika pasuje na każdej głębokości. Ukośnik na początku zakotwicza wzorzec w katalogu pliku ustawień. Ukośnik na końcu oznacza sam katalog.
- `rules` pozwala tylko wyłączyć regułę wartością `off`. Nazwa może zawierać `*`. Nazwa, która nie pasuje do żadnej reguły, daje ostrzeżenie.
- `baseline` to ścieżka względem pliku ustawień.
- Nieznana opcja albo zły typ to błąd z kodem 2, więc literówka nie osłabi bramki po cichu.

Plik ustawień, plik baseline i komentarze są częścią repozytorium, więc pull request może je zmienić. Przeglądaj takie zmiany jak kod. Wpis w `CODEOWNERS` dla dwóch pierwszych plików to ułatwia.

## Formaty wyjścia

- Terminal (domyślnie), czytelny raport z oceną.
- `--json`, do dalszego przetwarzania.
- `--sarif`, format SARIF 2.1.0 do zakładki Security w GitHub.
- `--diff <ref>`, skan tylko plików PHP zmienionych wobec ref gita (szybki skan dla pull requestów).
- `--suggest` i `--patch <plik>`, podpowiedzi napraw (opisane wyżej).
- `--extended`, dodatkowe reguły o niższej precyzji (opisane wyżej).
- `--lang <en|pl>`, język wyjścia (opisane wyżej).
- `--write-baseline <plik>` i `--baseline <plik>`, zgłaszanie tylko nowych znalezisk (opisane wyżej).
- `--config <plik>` i `--no-config`, plik ustawień (opisane wyżej).
- `--no-ignore-comments`, pomijanie komentarzy `wpcoderscan-ignore` (opisane wyżej).

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
      - uses: wpcoder23/wpcoderscan@v0.8.1
        with:
          path: .
          fail-on: high
          # extended: 'true'   # dodatkowe reguły o niższej precyzji
          # lang: pl           # komunikaty po polsku (domyślnie en)
          # baseline: .wpcoderscan-baseline.json   # zgłaszaj tylko znaleziska spoza tego pliku
          # config: .wpcoderscan.json              # plik ustawień, jeśli nie leży w korzeniu repozytorium
```

Akcja czyta `.wpcoderscan.json` z korzenia repozytorium, tak jak linia poleceń. `fail-on` albo `lang` ustawione w workflow mają pierwszeństwo przed plikiem. Pomiń je, gdy ma decydować plik.

## Licencja

Apache-2.0. Rdzeń jest otwarty. Adaptowane fragmenty z projektów MIT zachowują swoją notę licencyjną. Zobacz pliki `LICENSE` i `NOTICE`.
