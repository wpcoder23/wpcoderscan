# Historia zmian

## 0.3.1

Mniej fałszywych alarmów.

- Zmienna sprawdzona przed użyciem listą dozwolonych wartości nie jest już skażona. Dotyczy `in_array`, `array_key_exists`, `isset` na tablicy z kluczem ze zmiennej, `ctype_*`, `is_numeric`, zakotwiczonego wyrażenia regularnego i porównania z literałem. Działa w ciele `if`, w `else` po negacji i po wczesnym wyjściu.
- Klucz API Google jest heurystyką, nie wykryciem pewnym. Nie łamie już build, bo klucze do map bywają publiczne z założenia.
- `unserialize` z listą klas w `allowed_classes` to średnia heurystyka zamiast wykrycia pewnego.
- CI sprawdza CLI na podatnych i bezpiecznych próbkach, także z flagą `--extended`.
- Pomiar: na 200 najpopularniejszych wtyczkach z wordpress.org (49 tys. plików PHP) nie zostało żadne wykrycie pewne poza `register_setting`. Recall na zbiorze CVE bez zmian.

## 0.3.0

Więcej źródeł danych i lepsze wykrywanie na historycznych podatnościach.

- Nowe źródła danych od użytkownika: `filter_input` bez filtra czyszczącego, `php://input`, obiekt żądania REST (heurystyka), `add_query_arg` i `remove_query_arg` bez adresu (XSS) oraz atrybuty shortcode (zapisany XSS).
- Elementy tablicy są śledzone po literalnym kluczu. `$a['x']` z `$_GET` nie skazi już `$a['y']`.
- XSS: nowe ujścia `printf`, `vprintf`, `die`, `exit`, `wp_die` oraz `return` w callbacku shortcode. Odpowiedzi `json_encode` w tych ujściach są pomijane.
- Uchwyty `wp_ajax_*` i `admin_post_*` mogą być metodami klasy z tego samego pliku. Brak uprawnień przy obecnym nonce ma teraz poziom średni, brak nonce poziom wysoki.
- Nowa flaga `--extended` i wejście `extended` w akcji GitHub. Włącza regułę `wp.sqli.param_unprepared` (parametr funkcji wklejony do zapytania `$wpdb` bez `prepare`).
- Walidacja na 465 wersjach wtyczek z publicznie znanymi podatnościami: trafienia blisko linii podatności wzrosły dla SQL injection z 8 do 42, dla XSS z 35 do 102 i dla zapisanego XSS z 4 do 44.
- Hałas na 253 realnych wtyczkach i motywach nadal 0 awarii. Nowe znaleziska to głównie średnie heurystyki.

## 0.2.0

Podpowiedzi napraw.

- Nowa flaga `--suggest` pokazuje przy znalezisku gotową zmianę kodu. Skaner nic nie zapisuje w plikach źródłowych.
- Nowa flaga `--patch <plik>` zapisuje pełne podpowiedzi jako łatkę zgodną z `git apply`.
- XSS w `echo` i `print`: ucieczka dobrana do kontekstu HTML (`esc_html`, `esc_attr`, `esc_url`). Skrypty, style, zdarzenia i wartości bez cudzysłowu nie dostają podpowiedzi.
- `unserialize`: dopisanie `allowed_classes => false` do jednoargumentowego wywołania. Reguła nie zgłasza już wywołań, które to mają.
- Każda podpowiedź przechodzi weryfikację: ponowne parsowanie, ponowny skan, znalezisko musi zniknąć i nie mogą pojawić się nowe. Pliki z błędami składni nie dostają podpowiedzi.
- JSON zawiera pole `patch`, SARIF zawiera pole `fixes`.
- Zachowanie stylu pliku: nawiasy ze spacjami albo bez, `array()` albo `[]`, CRLF.

## 0.1.0

Pierwsze wydanie publiczne.

- Osiem reguł: SQL injection, trasy REST bez kontroli dostępu, RCE, `unserialize`, `register_setting`, zaszyte sekrety, XSS w `echo` i `print`, uchwyty akcji bez nonce i uprawnień.
- Lekka analiza skażenia danych w obrębie funkcji. Zmienna zasilona superglobalem jest śledzona, rzutowania i funkcje czyszczące zdejmują skażenie.
- Poziom pewności znaleziska: pewne łamią build, heurystyki tylko ostrzegają. Flaga `--strict` liczy też heurystyki.
- Raporty: terminal, JSON i SARIF 2.1.0.
- Tryb `--diff <ref>` do szybkiego skanu zmian w pull requestach.
- Akcja GitHub (composite) budowana ze źródeł repozytorium.
- Walidacja na 253 realnych wtyczkach i motywach WordPress: 0 awarii, około 42 tysiące plików PHP.
