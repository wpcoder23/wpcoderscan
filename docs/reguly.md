# Reguły WPCoderScan

Dokument opisuje każdą regułę: co zgłasza, jak wygląda podatny kod, jak wygląda kod poprawny i jaką pewność ma wykrycie. Wersja angielska: [rules.md](rules.md).

**Pewność.** Znalezisko *pewne* (firm) jest strukturalnie jednoznaczne i domyślnie łamie build. Znalezisko *heurystyczne* może być fałszywym alarmem, więc tylko ostrzega. Flaga `--strict` liczy też heurystyki do kodu wyjścia.

**Analiza danych.** Reguły śledzą dane użytkownika w obrębie funkcji i przez wywołania między funkcjami z tego samego pliku. Superglobal wprost w miejscu użycia daje wykrycie pewne. Zmienna zasilona superglobalem daje heurystykę. Inne źródła (obiekt żądania REST, atrybuty shortcode, `add_query_arg`) dają zawsze heurystykę o poziomie średnim. Gdy funkcja z pliku jest wołana z danymi użytkownika w argumencie, ten parametr uchodzi w niej za dane użytkownika. Działa to dla funkcji oraz wywołań `$this->metoda()`, `self::`, `static::` i `Klasa::`, w łańcuchach do sześciu wywołań. Wywołań do innych plików skaner nie śledzi. Funkcja, która przekazuje pierwszy parametr do `shortcode_atts`, uchodzi za obsługę shortcode, także gdy `add_shortcode` leży w innym pliku.

Rzutowanie na liczbę, `absint`, `intval`, `escapeshellarg` i `basename` zdejmują skażenie. Robi to też `$wpdb->prepare`, dla wartości podanych jako argumenty. Funkcje `esc_sql`, `addslashes` i `$wpdb->_escape` zdejmują je tylko dla wartości w cudzysłowie zapytania.

Zmienna sprawdzona przed użyciem listą dozwolonych wartości przestaje być skażona. Liczą się: `in_array`, `array_key_exists`, `isset` na tablicy z kluczem ze zmiennej, `ctype_*`, `is_numeric`, zakotwiczony regex, regex odrzucający każdy znak spoza zbioru, porównanie z literałem oraz wywołanie walidatora o nazwie w rodzaju `is_valid_*`, `is_allowed_*` albo `validate_*`. Sprawdzenie działa w ciele `if`, w gałęziach warunku trójargumentowego i po wczesnym wyjściu.

Wartość domyślna wpisana do elementu superglobala go nie czyści. `$_REQUEST['orderby'] = 'id'` w gałęzi `if ( empty( $_REQUEST['orderby'] ) )` zostawia wartość odwiedzającego w drugiej gałęzi, więc dalsza część funkcji nadal uznaje `$_REQUEST['orderby']` za dane użytkownika. Zapis, który sam czyta superglobal i go czyści (`$_GET['x'] = sanitize_text_field( $_GET['x'] )`, `(int) $_GET['x']`), nadal czyści.

**Gałęzie.** Zapis w ciele `if`, w `case` instrukcji `switch`, w pętli albo w `catch` nie musi się wykonać. Oczyszczenie zmiennej w takiej gałęzi nie oczyszcza jej dla kodu za konstrukcją, chyba że warunek sprawdza właśnie tę zmienną (`if ( ! empty( $name ) ) { $name = esc_html( $name ); }`). Zapis w jednej gałęzi nie jest widoczny w drugiej. Późniejszy pełny zapis w tej samej gałęzi zastępuje jej wcześniejsze zapisy. Skażenie przypisane w gałęzi dociera do kodu za nią. Skaner nie śledzi warunków przez kod, więc flaga wybierająca gałąź nie jest rozumiana.

Skażenie przenoszą funkcje, które zwracają fragment albo kopię argumentu. Są to funkcje tekstowe, takie jak `strtr`, `strstr`, `str_pad` i `wordwrap`, funkcje tablicowe, takie jak `array_shift`, `array_column` i `current`, oraz funkcje budujące ścieżki i adresy, takie jak `dirname`, `trailingslashit`, `admin_url` i `home_url`. Funkcje budujące adres przenoszą je tylko do znalezisk XSS. Host takiego adresu to twoja własna witryna, więc nie przenoszą go do znalezisk SSRF. Pozostałe nieznane funkcje nie przenoszą skażenia, więc skaner woli przeoczyć niż zasypać cię fałszywymi alarmami.

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
| `wp.file.path_traversal` (tryb `--extended`) | krytyczny, wysoki, średni, niski | pewna lub heurystyka | CWE-22, CWE-73 | nie |
| `wp.http.ssrf` (tryb `--extended`) | wysoki, średni, niski | pewna lub heurystyka | CWE-918 | nie |
| `wp.upload.unrestricted` (tryb `--extended`) | krytyczny, wysoki, średni, niski | pewna lub heurystyka | CWE-434 | nie |
| `wp.privilege.escalation` (tryb `--extended`) | krytyczny, wysoki | pewna lub heurystyka | CWE-269 | nie |
| `wp.option.arbitrary_update` (tryb `--extended`) | krytyczny, wysoki, średni, niski | pewna lub heurystyka | CWE-915 | nie |

## Bramka administratora

Pięć reguł rozszerzonych sprawdza, kto może dotrzeć do kodu. Kod dostępny tylko dla administratora nie jest otwartymi drzwiami dla odwiedzającego. Reguły ścieżek, adresów i wysyłania plików obniżają taki wynik do słabej wskazówki. Reguły kont i opcji go pomijają. Skaner uznaje za bramkę:

- `current_user_can( 'manage_options' )` i inne uprawnienia administratora (`manage_*`, `install_plugins`, `edit_users`, `promote_users` i podobne), także gdy uprawnienie stoi w zmiennej, która ma tylko taką wartość,
- `is_super_admin()`, sprawdzenie roli `administrator` i `$user->has_cap( 'manage_options' )`,
- wywołanie funkcji albo metody o nazwie sprawdzającej administratora (`user_is_admin`, `check_admin_permission`, `can_manage_options`) albo opakowania, które dostaje uprawnienie administratora, na przykład `$this->check_permission( 'manage_options' )`,
- stronę menu zarejestrowaną z takim uprawnieniem oraz trasę REST, której `permission_callback` je sprawdza albo ma nazwę sprawdzenia administratora. Callback strony albo trasy stoi za bramką,
- hook zarejestrowany w `if` ze sprawdzeniem uprawnienia administratora albo po wczesnym wyjściu dla pozostałych (`if ( ! current_user_can( 'manage_options' ) ) { return; }`). Samo `is_admin()` się nie liczy, bo pyta o ekran panelu, a nie o użytkownika. Funkcja zarejestrowana także bez takiego sprawdzenia jest otwarta,
- pomocnika, którego ten sam plik woła wyłącznie z kodu za bramką. Handler woła pomocnika, a ten woła kolejnego. Funkcja zarejestrowana także jako callback hooka albo wołana na obiekcie nieznanej klasy się nie liczy.

Nonce nie jest bramką, bo dostaje go każdy odwiedzający. `check_admin_referer()` sprawdza nonce, więc też nią nie jest. Uprawnienie zwykłego użytkownika (`edit_posts`) nie jest bramką. Skaner nie ocenia, czy sprawdzenie jest poprawne, i nie widzi bramki, która leży w innym pliku.

## Wyciszanie znalezisk

Przejrzane znalezisko można wyciszyć na trzy sposoby, od najwęższego do najszerszego.

- Komentarz wyciszający obok kodu: `// wpcoderscan-ignore wp.rce.dynamic -- powód`. Identyfikator reguły jest wymagany. `wpcoderscan-ignore-file` obejmuje cały plik.
- Plik baseline, który ukrywa znaleziska istniejące już w chwili wprowadzenia bramki.
- Opcje `rules` i `exclude` w `.wpcoderscan.json`, które wyłączają regułę albo pomijają ścieżki w całym projekcie.

Każdy sposób opisuje README.pl w części [Wdrożenie w istniejącym kodzie](../README.pl.md#wdrożenie-w-istniejącym-kodzie).

## wp.sqli.unprepared

Zapytanie `$wpdb` budowane z danych użytkownika bez `prepare`. Superglobal wprost w zapytaniu to wykrycie pewne i krytyczne. Zmienna zasilona superglobalem to heurystyka o wysokiej wadze. Zwykłe zmienne i nazwy tabel nie są zgłaszane.

`prepare` chroni tylko wartości podane jako argumenty. Dane użytkownika wklejone w tekst zapytania, który dostaje `prepare`, są nadal zgłaszane (`ORDER BY $orderby`, nazwa kolumny, nazwa tabeli zbudowana z danych).

`esc_sql`, `addslashes` i `$wpdb->_escape` chronią tylko tekst w cudzysłowie. Wartość przepuszczona przez nie, ale wstawiona poza cudzysłowem, jest zgłaszana z wysoką wagą. Dotyczy to liczby po `=`, nazwy kolumny, `LIMIT`, `ORDER BY` i tekstu w odwrotnych apostrofach. Zgłoszenie jest pewne, gdy superglobal stoi wprost w wyrażeniu. Jest heurystyką, gdy dane idą przez zmienną.

Reguła czyta też SQL, który WordPress składa za ciebie. Funkcja zarejestrowana na `posts_where`, `posts_orderby`, `posts_join` i pokrewnych hakach (`posts_search`, `posts_groupby`, `posts_fields`, `posts_clauses`, `posts_request`, `terms_clauses`, `comments_clauses`) zwraca tekst, który WordPress wkleja do zapytania. Dane użytkownika w tej wartości są zgłaszane. Zgłaszane są też dane przypisane do `query_where`, `query_orderby` i innych właściwości `query_*` obiektu zapytania (`pre_user_query`). Obowiązują te same zasady cudzysłowu: `esc_sql` chroni wartość w cudzysłowie, a poza nim nie chroni.

```php
// Podatne
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders WHERE id = " . $_GET['id'] );
add_filter( 'posts_orderby', function () { return $_GET['order']; } );
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders ORDER BY " . esc_sql( $_GET['orderby'] ) );

// Poprawne
$wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}orders WHERE id = %d", $_GET['id'] ) );
$orderby = in_array( $_GET['orderby'], array( 'date', 'total' ), true ) ? $_GET['orderby'] : 'date';
$wpdb->get_results( "SELECT * FROM {$wpdb->prefix}orders ORDER BY $orderby" );
```

## wp.xss.echo_superglobal

Dane użytkownika w `echo`, `print`, `printf`, `die`, `wp_die` albo w wartości zwracanej przez shortcode bez funkcji ucieczki. Odpowiedzi `json_encode` w `die`, `wp_die` i `printf` pomijamy, bo to zwykle AJAX.

Źródłem mogą być superglobale, `filter_input`, `add_query_arg` bez adresu i atrybuty shortcode. Atrybuty shortcode (`$atts`, klucze z `shortcode_atts` i `extract`) wpisuje autor wpisu, więc skutkiem jest zapisany XSS, a nie odbity. To heurystyka, bo skaner nie zna wszystkich własnych funkcji czyszczących projektu. Dla tej reguły skaner podaje gotową poprawkę, dobraną do miejsca w HTML. Opis w sekcji "Podpowiedzi napraw" w README.

Reguła zgłasza też dane użytkownika, które trafiają do HTML składanego w kodzie i niewypisywanego od razu. Liczą się trzy kształty. Funkcja zwraca tekst ze znacznikami HTML zbudowany z danych użytkownika. Zmienna zbiera taki HTML (`$html .= '<li>' . $_GET['x']`), a funkcja ją zwraca. Właściwość obiektu go przechowuje (`$this->content = '<div>' . $_GET['x'] . '</div>'`). Kod, który wypisuje wynik, często leży w innym pliku, więc takie zgłoszenia mają wagę średnią. Dane użytkownika wklejone do `do_shortcode()` są zgłaszane z tego samego powodu, bo odwiedzający może wtedy dodać własny shortcode albo atrybut.

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

## wp.file.path_traversal

Reguła rozszerzona, włączana flagą `--extended`. Plik jest czytany, zapisywany albo usuwany pod ścieżką, która pochodzi od użytkownika. Atakujący może odczytać `wp-config.php`, nadpisać plik kodem PHP albo usunąć plik i przejąć witrynę.

Reguła obejmuje `file_get_contents`, `readfile`, `file`, `fopen`, `parse_ini_file`, `simplexml_load_file`, `highlight_file`, `copy`, `rename`, `file_put_contents`, `unlink`, `wp_delete_file` oraz metody `$wp_filesystem` `get_contents`, `put_contents`, `copy`, `move` i `delete`. Ścieżka wzięta wprost z superglobala to wykrycie pewne. Zmienna zasilona danymi użytkownika to heurystyka. Zapis ma poziom krytyczny w wykryciu pewnym i wysoki w heurystyce. Odczyt i usunięcie mają poziom wysoki w wykryciu pewnym i średni w heurystyce.

Reguła nie zgłasza ścieżki zredukowanej przez `basename`, `wp_basename` albo `sanitize_file_name`. Pomija ścieżkę sprawdzoną w tej samej funkcji (`validate_file`, `realpath`, szukanie `..`) oraz adres z ustalonym hostem, bo adresy obejmuje reguła SSRF. Pomija ścieżkę, w której dane stoją tylko w nazwie pliku za stałym fragmentem (`'img-' . $id`). Pomija też odczyt i usunięcie pliku o stałym, niegroźnym rozszerzeniu (`.jpg`, `.json`, `.csv`, `.txt`). Zapis pod taką ścieżką to heurystyka o niskim poziomie, bo plik nie wykona kodu. Funkcja za bramką na uprawnienie administratora to także heurystyka o niskim poziomie.

```php
// Podatne
echo file_get_contents( WP_CONTENT_DIR . '/uploads/' . $_GET['file'] );
unlink( $_POST['path'] );

// Poprawne
$name = wp_basename( $_GET['file'] );
$base = realpath( WP_CONTENT_DIR . '/uploads' );
$path = realpath( $base . '/' . $name );
if ( $path && str_starts_with( $path, $base . DIRECTORY_SEPARATOR ) ) {
	echo file_get_contents( $path );
}
```

## wp.http.ssrf

Reguła rozszerzona, włączana flagą `--extended`. Serwer wysyła żądanie HTTP pod adres, który pochodzi od użytkownika. Atakujący może skłonić serwer do wywołania usług wewnętrznych, adresów metadanych chmury albo obcych hostów.

Reguła obejmuje `wp_remote_get`, `wp_remote_post`, `wp_remote_request`, `wp_remote_head`, `wp_remote_fopen`, `get_headers`, `curl_init`, opcję `CURLOPT_URL` w `curl_setopt` i `curl_setopt_array`, `fsockopen`, `pfsockopen` oraz `stream_socket_client`. O wyniku rozstrzyga początek adresu, bo zawiera schemat i host. Dane użytkownika doklejone za ustalonym hostem (`'https://api.example.com/?q=' . $q`) zmieniają tylko zapytanie, więc ich nie zgłaszamy. Host ustalony w zmiennej liczy się jako ustalony. Funkcje `wp_safe_remote_*` odrzucają adresy wewnętrzne, więc zostają poza regułą. Tak samo adres, który funkcja sprawdza przez `wp_http_validate_url`, `parse_url` albo `wp_parse_url`. Wykrycie pewne ma poziom wysoki. Heurystyka ma poziom średni. Funkcja za bramką na uprawnienie administratora to heurystyka o niskim poziomie.

```php
// Podatne
$response = wp_remote_get( $_GET['url'] );

// Poprawne
$response = wp_safe_remote_get( esc_url_raw( $_GET['url'] ) );
$response = wp_remote_get( 'https://api.example.com/v1/items?q=' . rawurlencode( $_GET['q'] ) );
```

## wp.upload.unrestricted

Reguła rozszerzona, włączana flagą `--extended`. Wysłany plik jest zapisywany pod nazwą od klienta, a funkcja nie sprawdza typu pliku. Atakujący może wysłać skrypt PHP i uruchomić kod.

Są dwie postacie. Pierwsza to `move_uploaded_file` z miejscem docelowym zbudowanym z danych użytkownika. Druga to `wp_handle_upload` albo `wp_handle_sideload` z `'test_type' => false`, co wyłącza kontrolę typu w rdzeniu. Nazwa wzięta wprost z `$_FILES` to wykrycie pewne. Plik o nieznanym pochodzeniu, na przykład z parametru funkcji, to heurystyka o poziomie średnim. Funkcja za bramką na uprawnienie administratora to heurystyka o niskim poziomie.

Sprawdzenie liczy się, gdy stoi przed zapisem. Chodzi o wywołanie `wp_check_filetype`, `wp_check_filetype_and_ext`, `getimagesize`, `exif_imagetype`, `mime_content_type` albo `finfo_*`. Liczy się też odczyt rozszerzenia przez `pathinfo` razem z porównaniem z listą, porównanie pola `type` od klienta z listą, sprawdzenie końcówki nazwy (`str_ends_with( $nazwa, '.json' )`) oraz wywołanie funkcji, której nazwa mówi, że waliduje typ pliku (`is_allowed_file_type`, `validate_upload`). Sprawdzenie po zapisie liczy się tylko wtedy, gdy funkcja usuwa plik, który go nie przeszedł. Stałe rozszerzenie docelowe, które nie wykonuje kodu (`.jpg`, `.json`), kończy zgłoszenie. Stałe `.php` go nie kończy, bo treść pliku wybiera klient.

```php
// Podatne
move_uploaded_file( $_FILES['file']['tmp_name'], WP_CONTENT_DIR . '/uploads/' . $_FILES['file']['name'] );

// Poprawne
$check = wp_check_filetype( $_FILES['file']['name'], array( 'jpg|jpeg' => 'image/jpeg', 'png' => 'image/png' ) );
if ( $check['ext'] ) {
	move_uploaded_file( $_FILES['file']['tmp_name'], WP_CONTENT_DIR . '/uploads/' . sanitize_file_name( $_FILES['file']['name'] ) );
}
```

## wp.privilege.escalation

Reguła rozszerzona, włączana flagą `--extended`. Rola, logowanie albo uprawnienia konta są sterowane przez żądanie. Atakujący może założyć konto administratora albo zalogować się jako dowolny użytkownik.

Są cztery postacie. Rola z żądania trafia do `wp_insert_user`, `wp_update_user`, `set_role`, `add_role` albo `add_cap`, albo całe żądanie idzie jako dane konta (`wp_insert_user( $_POST )`). Klucz meta użytkownika z żądania trafia do `update_user_meta` albo `add_user_meta`, więc żądanie może zapisać `wp_capabilities`. Wartość z żądania trafia do meta uprawnień. Identyfikator użytkownika z żądania trafia do `wp_set_auth_cookie` albo `wp_set_current_user`, a nic w funkcji nie potwierdza, kim jest odwiedzający.

Dowodem tożsamości jest wywołanie `wp_check_password`, `wp_signon`, `hash_equals`, `password_verify`, `hash_hmac`, `openssl_verify`, żądanie do dostawcy logowania, kontrola uprawnienia albo funkcja o nazwie w rodzaju `verify_*`, `authenticate_*` lub `decode_jwt`. Nonce nie jest dowodem, bo dostaje go każdy odwiedzający. Funkcja za bramką na uprawnienie administratora nie jest zgłaszana. Dotyczy to też strony menu i trasy REST, które rejestrują się z takim uprawnieniem. Logowanie w funkcji, która sprawdza środowisko deweloperskie, jest pomijane, bo na produkcji nie działa.

```php
// Podatne
wp_insert_user( array( 'user_login' => $_POST['login'], 'user_pass' => $_POST['pass'], 'role' => $_POST['role'] ) );
wp_set_auth_cookie( (int) $_GET['user_id'] );

// Poprawne
wp_insert_user( array( 'user_login' => sanitize_user( $_POST['login'] ), 'user_pass' => $_POST['pass'], 'role' => 'subscriber' ) );
```

## wp.option.arbitrary_update

Reguła rozszerzona, włączana flagą `--extended`. Nazwa opcji WordPressa pochodzi od użytkownika. Atakujący może zmienić `default_role` albo `users_can_register` i przejąć witrynę, albo usunąć opcję rdzenia i ją zepsuć.

Reguła obejmuje `update_option`, `add_option`, `delete_option` oraz ich warianty dla witryny i sieci. Stały przedrostek w nazwie (`'demo_' . $key`) ogranicza zakres do opcji wtyczki, więc go nie zgłaszamy. Stały koniec nazwy o długości co najmniej pięciu znaków (`$_POST['addon'] . '_notice_ignore'`) obniża wynik do heurystyki o niskim poziomie. Wyjątkiem są końcówki opcji ról (`user_roles`, `capabilities`). Wartość podana na stałe (`update_option( $nazwa, true )`) obniża wynik o jeden stopień, bo atakujący wybiera nazwę, ale nie wartość. Sprawdzenie przedrostka przed zapisem jest strażnikiem, gdy przedrostek ma co najmniej cztery znaki: `strpos( $key, 'demo_' ) !== 0` z wyjściem albo `str_starts_with( $key, 'demo_' )` w warunku. Luźne porównanie `!= 0` strażnikiem nie jest, bo `false == 0`. Funkcja za bramką na uprawnienie administratora nie jest zgłaszana. Dotyczy to też strony menu i trasy REST, które rejestrują się z takim uprawnieniem.

```php
// Podatne
update_option( $_POST['name'], $_POST['value'] );

// Poprawne
$allowed = array( 'demo_color', 'demo_size' );
if ( in_array( $_POST['name'], $allowed, true ) ) {
	update_option( $_POST['name'], sanitize_text_field( $_POST['value'] ) );
}
```

## wp.auth.unprotected_action

Uchwyt `admin_post_*` albo `wp_ajax_*`, także w wariancie `nopriv`, który zmienia stan (zapis opcji, meta, bazy, usunięcie) bez weryfikacji nonce i bez kontroli uprawnień. Uchwyt może być funkcją, domknięciem albo metodą klasy z tego samego pliku (`[ $this, 'm' ]`, `[ self::class, 'm' ]`, `[ Klasa::class, 'm' ]`, `'Klasa::m'`). Brak uprawnień przy obecnym nonce ma poziom średni, bo atak wymaga zalogowanego konta. Brak nonce albo brak obu zabezpieczeń ma poziom wysoki. Zgłoszenie wskazuje definicję uchwytu, a nie wywołanie `add_action`. To heurystyka.

Reguła idzie za wywołaniami funkcji i metod z tego samego pliku. Nonce albo kontroli uprawnień szuka do trzech wywołań w głąb. Zmianę stanu w pomocniku liczy tylko do dwóch wywołań w głąb i tylko wtedy, gdy pomocnik dostaje dane z żądania w argumencie albo sam czyta `$_GET`, `$_POST`, `$_REQUEST` lub `$_FILES`. Pomocnik, który tylko porządkuje własne dane wtyczki, nie mówi nic o tym, kto steruje uchwytem.

Reguła pomija sześć rodzajów uchwytów.

- Uchwyty, które wołają pomocnika o nazwie kontrolnej, na przykład zawierającej `nonce`, `verify`, `permission`, `capability`, `can_`, `is_user_logged_in`, `validate_ajax` albo `legit`. Skaner czyta tak samo snake_case i camelCase, więc `isUserAllowedToEdit()` liczy się jak `is_user_allowed_to_edit()`. Nazwy, które tylko brzmią podobnie, nie liczą się. Są to na przykład `wp_get_current_user`, `get_access_token` i `wp_kses_allowed_html`.
- Uchwyty, które zapisują wyłącznie profil zalogowanego użytkownika, na przykład `update_user_meta( get_current_user_id(), ... )` albo `update_user_option( $user->ID, ... )` po `$user = wp_get_current_user()`. Zmieniają tylko dane wołającego.
- Uchwyty o nazwie zamykającej powiadomienie, baner, wskazówkę albo przewodnik po panelu (na przykład `dismiss`, `notice`, `banner`, `pointer`, `welcome`, `promo`, `remind`), które zapisują opcję, transjent albo meta użytkownika pod kluczem niezależnym od żądania. Taki zapis pamięta stan interfejsu, a nie dane serwisu.
- Uchwyty, które porównują dane z żądania z sekretem zapisanym w opcji albo transjencie. To token jednorazowy, który robi to, co nonce. Porównanie to `===`, `!==`, `==`, `!=` albo `hash_equals`. Jedna strona musi pochodzić z żądania. Druga musi czytać `get_option`, `get_site_option`, `get_transient` albo `get_site_transient`, wprost albo przez zmienną, i nie może zależeć od żądania. Skrót zapisanej wartości (`hash_hmac`) jest w porządku.
- Uchwyty, których callback ma wymagany parametr, czyli bez wartości domyślnej i niewariadyczny. WordPress woła haki `admin_post_*` i `wp_ajax_*` bez argumentów, więc takie wywołanie kończy się błędem `ArgumentCountError`, zanim callback cokolwiek zmieni.
- Uchwyty, które tylko usuwają transjent pod kluczem niezależnym od żądania. To czyszczenie pamięci podręcznej, które nie zmienia danych serwisu.

Reguła nie żąda kontroli uprawnień w uchwycie, który ten sam plik rejestruje jednocześnie pod `wp_ajax_*` i `wp_ajax_nopriv_*` z tym samym callbackiem. Taki uchwyt jest publiczny z założenia, więc liczy się tylko nonce. Wyjątek kończy się, gdy uchwyt zmienia coś, czego nie zmienia zwykły publiczny formularz. Chodzi o opcję serwisu, konto innej osoby albo jej hasło, rolę lub uprawnienie, wtyczkę lub motyw, istniejącą treść albo plik. Taki uchwyt przez hak `nopriv` jest otwarty także dla niezalogowanych, więc zgłoszenie o uprawnieniach zostaje.

Haki `init` i `admin_init` nie są sprawdzane. Test na popularnych wtyczkach dał tam szum i żadnej dodatkowej podatności.

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

`register_setting` bez `sanitize_callback`. Wartość opcji jest zapisywana bez walidacji. Trzeci argument, który jest tablicą callable z dwóch elementów bez kluczy, na przykład `[ $this, 'sanitize' ]` albo `array( __CLASS__, 'sanitize' )`, liczy się jako sanitize callback. WordPress zamienia taki trzeci argument na `array( 'sanitize_callback' => $callable )`.

```php
// Podatne
register_setting( 'demo_group', 'demo_option' );

// Poprawne
register_setting( 'demo_group', 'demo_option', array( 'sanitize_callback' => 'sanitize_text_field' ) );
```

## wp.secret.hardcoded

Zaszyte sekrety w kodzie. Klucze dostawców o znanym formacie (AWS, Stripe live, GitHub, Slack, SendGrid, klucz prywatny z treścią) są wykryciem pewnym. Klucz API Google to heurystyka o wysokim poziomie, bo klucze do map w przeglądarce bywają publiczne z założenia, a ten sam format mają klucze płatnych API. Wykrycie po nazwie zmiennej (`password`, `secret`, `api_key` i podobne) jest heurystyką i wymaga wartości, która wygląda na sekret: co najmniej 12 znaków, litery i cyfry, bez spacji, nie adres URL, nie tekst zastępczy i nie kształt nazwy. Nazwa to małe litery i cyfry rozdzielone znakami `_`, `.`, `-` albo `/`, ze słowem z czterech liter i bez serii trzech cyfr (`my_plugin_secret_key`, `cdn.s3.secret`, `/oauth2/v2.0/token`). To nazwa opcji, klucz konfiguracji albo ścieżka.

```php
// Podatne
$api_key = 'wartość-prawdziwego-klucza';

// Poprawne
$api_key = defined( 'DEMO_API_KEY' ) ? DEMO_API_KEY : '';   // stała w wp-config.php poza repozytorium
```

Jeśli klucz trafił do repozytorium, uznaj go za ujawniony i unieważnij. Samo usunięcie z kodu nie wystarczy, bo klucz zostaje w historii.
