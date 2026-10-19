# Reguły WPCoderScan

Dokument opisuje każdą regułę: co zgłasza, jak wygląda podatny kod, jak wygląda kod poprawny i jaką pewność ma wykrycie. Wersja angielska: [rules.md](rules.md).

**Pewność.** Znalezisko *pewne* (firm) jest strukturalnie jednoznaczne i domyślnie łamie build. Znalezisko *heurystyczne* może być fałszywym alarmem, więc tylko ostrzega. Flaga `--strict` liczy też heurystyki do kodu wyjścia.

**Analiza danych.** Reguły śledzą dane użytkownika w obrębie funkcji i przez wywołania między funkcjami z tego samego pliku. Superglobal wprost w miejscu użycia daje wykrycie pewne. Zmienna zasilona superglobalem daje heurystykę. Inne źródła (obiekt żądania REST, atrybuty shortcode, `add_query_arg`) dają zawsze heurystykę o poziomie średnim. Gdy funkcja z pliku jest wołana z danymi użytkownika w argumencie, ten parametr uchodzi w niej za dane użytkownika. Działa to dla funkcji oraz wywołań `$this->metoda()`, `self::`, `static::` i `Klasa::`, w łańcuchach do sześciu wywołań. Wywołań do innych plików skaner nie śledzi. Funkcja, która przekazuje pierwszy parametr do `shortcode_atts`, uchodzi za obsługę shortcode, także gdy `add_shortcode` leży w innym pliku.

Rzutowanie na liczbę, `absint`, `intval`, `escapeshellarg` i `basename` zdejmują skażenie. Robi to też `$wpdb->prepare`, dla wartości podanych jako argumenty. Funkcje `esc_sql`, `addslashes` i `$wpdb->_escape` zdejmują je tylko dla wartości w cudzysłowie zapytania.

Zmienna sprawdzona przed użyciem listą dozwolonych wartości przestaje być skażona. Liczą się: `in_array`, `array_key_exists`, `isset` na tablicy z kluczem ze zmiennej, `ctype_*`, `is_numeric`, zakotwiczony regex, regex odrzucający każdy znak spoza zbioru, porównanie z literałem oraz wywołanie walidatora o nazwie w rodzaju `is_valid_*`, `is_allowed_*` albo `validate_*`. Sprawdzenie działa w ciele `if`, w gałęziach warunku trójargumentowego i po wczesnym wyjściu.

Nieznane funkcje nie przenoszą skażenia, więc skaner woli przeoczyć niż zasypać cię fałszywymi alarmami.

| Reguła | Poziom | Pewność | CWE | Podpowiedź naprawy |
| --- | --- | --- | --- | --- |
| `wp.sqli.unprepared` | krytyczny, wysoki | pewna lub heurystyka | CWE-89 | nie |
| `wp.xss.echo_superglobal` | wysoki, średni | heurystyka | CWE-79 | tak |
| `wp.unserialize.user_input` | wysoki | pewna | CWE-502 | tak |
| `wp.rce.dynamic` | krytyczny, wysoki, średni | pewna lub heurystyka | CWE-94 | nie |
| `wp.rest.no_permission_callback` | wysoki, średni | pewna lub heurystyka | CWE-862 | nie |
| `wp.auth.unprotected_action` | wysoki | heurystyka | CWE-352, CWE-862 | nie |
| `wp.option.no_sanitize_callback` | średni | pewna | CWE-20 | nie |
| `wp.secret.hardcoded` | krytyczny, wysoki, średni | pewna lub heurystyka | CWE-798 | nie |
| `wp.sqli.param_unprepared` (tryb `--extended`) | średni | heurystyka | CWE-89 | nie |

## wp.sqli.unprepared

Zapytanie `$wpdb` budowane z danych użytkownika bez `prepare`. Superglobal wprost w zapytaniu to wykrycie pewne i krytyczne. Zmienna zasilona superglobalem to heurystyka o wysokiej wadze. Zwykłe zmienne i nazwy tabel nie są zgłaszane.

`prepare` chroni tylko wartości podane jako argumenty. Dane użytkownika wklejone w tekst zapytania, który dostaje `prepare`, są nadal zgłaszane (`ORDER BY $orderby`, nazwa kolumny, nazwa tabeli zbudowana z danych).

`esc_sql`, `addslashes` i `$wpdb->_escape` chronią tylko tekst w cudzysłowie. Wartość przepuszczona przez nie, ale wstawiona poza cudzysłowem, jest zgłaszana z wysoką wagą. Dotyczy to liczby po `=`, nazwy kolumny, `LIMIT`, `ORDER BY` i tekstu w odwrotnych apostrofach. Zgłoszenie jest pewne, gdy superglobal stoi wprost w wyrażeniu. Jest heurystyką, gdy dane idą przez zmienną.

```php
// Podatne
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders WHERE id = " . $_GET['id'] );
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders ORDER BY " . esc_sql( $_GET['orderby'] ) );

// Poprawne
$wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}orders WHERE id = %d", $_GET['id'] ) );
$orderby = in_array( $_GET['orderby'], array( 'date', 'total' ), true ) ? $_GET['orderby'] : 'date';
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders ORDER BY $orderby" );
```

## wp.xss.echo_superglobal

Dane użytkownika w `echo`, `print`, `printf`, `die`, `wp_die` albo w wartości zwracanej przez shortcode bez funkcji ucieczki. Odpowiedzi `json_encode` w `die`, `wp_die` i `printf` pomijamy, bo to zwykle AJAX.

Źródłem mogą być superglobale, `filter_input`, `add_query_arg` bez adresu i atrybuty shortcode. Atrybuty shortcode (`$atts`, klucze z `shortcode_atts` i `extract`) wpisuje autor wpisu, więc skutkiem jest zapisany XSS, a nie odbity. To heurystyka, bo skaner nie zna wszystkich własnych funkcji czyszczących projektu. Dla tej reguły skaner podaje gotową poprawkę, dobraną do miejsca w HTML. Opis w sekcji "Podpowiedzi napraw" w README.

```php
// Podatne
<h2>Wyniki dla: <?php echo $_GET['q']; ?></h2>
<input value="<?php echo $_GET['q']; ?>">
<a href="<?php echo $_GET['back']; ?>">Wróć</a>

// Poprawne
<h2>Wyniki dla: <?php echo esc_html( $_GET['q'] ); ?></h2>
<input value="<?php echo esc_attr( $_GET['q'] ); ?>">
<a href="<?php echo esc_url( $_GET['back'] ); ?>">Wróć</a>
```

## wp.unserialize.user_input

`unserialize` albo `maybe_unserialize` na danych z superglobala albo na zmiennej zasilonej danymi użytkownika (heurystyka). Wywołanie wewnątrz `if ( is_serialized_string( $x ) )` jest pomijane, bo taki tekst nie może zawierać obiektu. Pozwala wstrzyknąć obiekt PHP i uruchomić łańcuch gadżetów z innej wtyczki. Wywołanie, które ma drugi argument `array( 'allowed_classes' => false )`, nie jest zgłaszane. Lista klas zamiast `false` obniża zgłoszenie do średniej heurystyki, bo ryzyko zostaje, jeśli któraś z klas ma metody magiczne. Skaner podpowiada tę poprawkę dla jednoargumentowego `unserialize`.

```php
// Podatne
$settings = unserialize( $_POST['settings'] );

// Poprawne
$settings = json_decode( wp_unslash( $_POST['settings'] ), true );
// albo, gdy musisz zostać przy serializacji
$settings = unserialize( $_POST['settings'], array( 'allowed_classes' => false ) );
```

## wp.rce.dynamic

Wykonanie kodu albo polecenia z danych użytkownika: `eval`, `include` i `require` ze ścieżką od użytkownika, backticki oraz rodzina `exec`, `system`, `shell_exec`, `passthru`. Dane z superglobala wprost są pewne i krytyczne. Przez zmienną to heurystyka. `eval` bez danych użytkownika to średnia heurystyka.

Ujściami są też funkcje ładujące szablon: `get_template_part`, `locate_template`, `load_template`, `wc_get_template`, `wc_get_template_part` i `wc_get_template_html` oraz metody, których nazwa mówi, że ładują szablon (`get_template`, `load_template`, `render_template`, `include_template` i podobne). Nazwa szablonu zbudowana z danych użytkownika może zawierać `../` i dołączyć plik PHP spoza katalogu szablonów. Funkcja ładująca zdefiniowana w tym samym pliku nie jest zgłaszana przy wywołaniu. Zgłaszany jest `include` w jej wnętrzu, gdy wywołanie przekazuje dane użytkownika.

```php
// Podatne
include $_GET['template'] . '.php';
get_template_part( 'parts/' . $_GET['part'] );

// Poprawne
$allowed = array( 'list', 'single' );
$name    = in_array( $_GET['template'], $allowed, true ) ? $_GET['template'] : 'list';
include __DIR__ . '/templates/' . $name . '.php';
```

## wp.rest.no_permission_callback

Trasa REST bez `permission_callback`. Brak tego argumentu to wykrycie pewne. `__return_true` na trasie zmieniającej dane to heurystyka. Trasy tylko do odczytu (`GET`, `READABLE`) z `__return_true` pomijamy, bo to częsty i zamierzony wzorzec.

```php
// Podatne
register_rest_route( 'demo/v1', '/orders', array(
	'methods'  => 'POST',
	'callback' => 'demo_save_order',
) );

// Poprawne
register_rest_route( 'demo/v1', '/orders', array(
	'methods'             => 'POST',
	'callback'            => 'demo_save_order',
	'permission_callback' => function () {
		return current_user_can( 'manage_options' );
	},
) );
```

## wp.sqli.param_unprepared

Reguła rozszerzona, włączana flagą `--extended`. Zgłasza parametr funkcji wklejony do zapytania `$wpdb` bez `prepare`, gdy nic w pliku nie przekazuje do niego danych użytkownika. Skaner nie widzi wywołujących z innych plików, więc nie wie, czy do parametru trafiają dane od użytkownika. Dlatego to zawsze heurystyka o poziomie średnim. Gdy wywołanie z tego samego pliku przekazuje dane użytkownika, zgłasza to zwykła reguła `wp.sqli.unprepared`. Znaleziska, które pokrywa zwykła reguła, są pomijane.

```php
// Podatne, jeśli funkcję wołają dane od użytkownika
function demo_get_order( $id ) {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}orders WHERE id = " . $id );
}

// Poprawne
function demo_get_order( $id ) {
	global $wpdb;
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}orders WHERE id = %d", $id ) );
}
```

## wp.auth.unprotected_action

Uchwyt `admin_post_*` albo `wp_ajax_*`, który zmienia stan (zapis opcji, meta, bazy, usunięcie) bez weryfikacji nonce i bez kontroli uprawnień. Uchwyt może być funkcją, domknięciem albo metodą klasy z tego samego pliku (`[ $this, 'm' ]`, `[ self::class, 'm' ]`, `[ Klasa::class, 'm' ]`, `'Klasa::m'`). Brak uprawnień przy obecnym nonce ma poziom średni, bo atak wymaga zalogowanego konta. Brak nonce albo brak obu zabezpieczeń ma poziom wysoki. Reguła pomija uchwyty, które wołają pomocnika o nazwie kontrolnej (zawierającej na przykład `nonce`, `verify`, `permission`, `capability`). Zgłoszenie wskazuje definicję uchwytu, a nie wywołanie `add_action`. To heurystyka.

```php
// Podatne
add_action( 'wp_ajax_demo_delete', function () {
	delete_option( 'demo_data' );
	wp_send_json_success();
} );

// Poprawne
add_action( 'wp_ajax_demo_delete', function () {
	check_ajax_referer( 'demo_delete' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error( null, 403 );
	}
	delete_option( 'demo_data' );
	wp_send_json_success();
} );
```

## wp.option.no_sanitize_callback

`register_setting` bez `sanitize_callback`. Wartość opcji jest zapisywana bez walidacji.

```php
// Podatne
register_setting( 'demo_group', 'demo_option' );

// Poprawne
register_setting( 'demo_group', 'demo_option', array( 'sanitize_callback' => 'sanitize_text_field' ) );
```

## wp.secret.hardcoded

Zaszyte sekrety w kodzie. Klucze dostawców o znanym formacie (AWS, Stripe live, GitHub, Slack, SendGrid, klucz prywatny z treścią) są wykryciem pewnym. Klucz API Google to heurystyka o wysokim poziomie, bo klucze do map w przeglądarce bywają publiczne z założenia, a ten sam format mają klucze płatnych API. Wykrycie po nazwie zmiennej (`password`, `secret`, `api_key` i podobne) jest heurystyką i wymaga wartości, która wygląda na sekret: co najmniej 12 znaków, litery i cyfry, bez spacji, nie adres URL, nie tekst zastępczy.

```php
// Podatne
$api_key = 'wartość-prawdziwego-klucza';

// Poprawne
$api_key = defined( 'DEMO_API_KEY' ) ? DEMO_API_KEY : '';   // stała w wp-config.php poza repozytorium
```

Jeśli klucz trafił do repozytorium, uznaj go za ujawniony i unieważnij. Samo usunięcie z kodu nie wystarczy, bo klucz zostaje w historii.
