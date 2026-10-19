// Polski katalog komunikatów. Te same klucze i te same zmienne w klamrach co w en.ts.
import type { MessageKey } from './en';

export const pl: Record<MessageKey, string> = {
  // Tytuły reguł (raport SARIF).
  'rule.wp.sqli.unprepared.title': 'Zapytanie do bazy bez $wpdb->prepare z danymi od użytkownika',
  'rule.wp.sqli.param_unprepared.title': 'Parametr funkcji wklejony do zapytania $wpdb bez prepare',
  'rule.wp.rest.no_permission_callback.title': 'Trasa REST API bez kontroli dostępu',
  'rule.wp.rce.dynamic.title': 'Dynamiczne wykonanie kodu lub polecenia systemowego',
  'rule.wp.unserialize.user_input.title': 'unserialize na danych od użytkownika',
  'rule.wp.option.no_sanitize_callback.title': 'register_setting bez sanitize_callback',
  'rule.wp.secret.hardcoded.title': 'Zaszyty sekret w kodzie',
  'rule.wp.xss.echo_superglobal.title': 'Dane użytkownika w echo lub print bez ucieczki',
  'rule.wp.auth.unprotected_action.title': 'Uchwyt akcji bez weryfikacji nonce lub uprawnień',
  'rule.wp.file.path_traversal.title': 'Odczyt, zapis lub usunięcie pliku pod ścieżką od użytkownika',
  'rule.wp.http.ssrf.title': 'Żądanie HTTP pod adres od użytkownika',
  'rule.wp.upload.unrestricted.title': 'Wysyłanie pliku bez sprawdzenia typu',
  'rule.wp.privilege.escalation.title': 'Rola, logowanie lub uprawnienia konta sterowane przez żądanie',
  'rule.wp.option.arbitrary_update.title': 'Nazwa opcji sterowana danymi od użytkownika',

  // Pochodzenie danych.
  'origin.request': 'z żądania REST',
  'origin.url': 'z adresu bieżącej strony (add_query_arg bez adresu)',
  'origin.param': 'z parametru funkcji',
  'origin.shortcode': 'z atrybutów shortcode',
  'origin.caller': 'przekazane przez wywołanie w tym pliku, pierwotnie od użytkownika',
  'origin.user': 'od użytkownika',

  // SQL injection.
  'sqli.fix':
    'Użyj $wpdb->prepare() z placeholderami %s, %d, %f i przekaż dane jako argumenty, zamiast sklejać je w tekst zapytania.',
  'sqli.direct': 'Wywołanie $wpdb->{method}() wkleja dane od użytkownika do zapytania bez prepare. Grozi SQL injection.',
  'sqli.viaVar':
    'Wywołanie $wpdb->{method}() używa zmiennej {var}, która zawiera dane {origin}, i buduje z niej zapytanie bez prepare. Prawdopodobny SQL injection.',
  'sqli.unquoted':
    'Wywołanie $wpdb->{method}() wkleja dane od użytkownika do zapytania poza cudzysłowem. Funkcje esc_sql() i addslashes() chronią tylko tekst w cudzysłowie. Liczba, nazwa kolumny albo ORDER BY zbudowane w ten sposób nadal pozwalają na SQL injection.',
  'sqli.unquoted.viaVar':
    'Wywołanie $wpdb->{method}() wkleja zmienną {var}, która zawiera dane {origin}, do zapytania poza cudzysłowem. Funkcje esc_sql() i addslashes() chronią tylko tekst w cudzysłowie. Liczba, nazwa kolumny albo ORDER BY zbudowane w ten sposób nadal pozwalają na SQL injection.',
  'sqli.unquoted.fix':
    'Rzutuj liczby na int albo użyj absint. Nazwy kolumn i kierunek sortowania sprawdź na liście dozwolonych wartości. Sama ucieczka nie chroni wartości, która stoi poza cudzysłowem.',
  'sqli.clause.direct':
    'Dane od użytkownika trafiają do fragmentu zapytania {target} bez prepare. WordPress dopisuje ten tekst do zapytania. Grozi SQL injection.',
  'sqli.clause.viaVar':
    'Zmienna {var}, która zawiera dane {origin}, trafia do fragmentu zapytania {target} bez prepare. WordPress dopisuje ten tekst do zapytania. Prawdopodobny SQL injection.',
  'sqli.clause.unquoted':
    'Dane od użytkownika trafiają do fragmentu zapytania {target} poza cudzysłowem. Funkcje esc_sql() i addslashes() chronią tylko tekst w cudzysłowie. Liczba, nazwa kolumny albo ORDER BY zbudowane w ten sposób nadal pozwalają na SQL injection.',
  'sqli.clause.unquoted.viaVar':
    'Zmienna {var}, która zawiera dane {origin}, trafia do fragmentu zapytania {target} poza cudzysłowem. Funkcje esc_sql() i addslashes() chronią tylko tekst w cudzysłowie. Liczba, nazwa kolumny albo ORDER BY zbudowane w ten sposób nadal pozwalają na SQL injection.',
  'sqli.param.message':
    'Wywołanie $wpdb->{method}() buduje zapytanie z parametru {var} funkcji bez prepare. Jeśli do funkcji trafiają dane od użytkownika, grozi SQL injection.',
  'sqli.param.fix':
    'Użyj $wpdb->prepare() z placeholderami, a dla liczb rzutuj na int albo absint. Nazwy kolumn i kierunek sortowania sprawdź na liście dozwolonych wartości.',

  // XSS.
  'xss.fix':
    'Opakuj dane funkcją ucieczki zależną od kontekstu: esc_html w treści, esc_attr w atrybucie, esc_url w adresie. Dla HTML z tagami użyj wp_kses_post.',
  'xss.direct': 'Dane {origin} trafiają do {sink} bez funkcji ucieczki. Grozi {kind}.',
  'xss.viaVar': 'Zmienna {var} zawiera dane {origin} i trafia do {sink} bez funkcji ucieczki. Możliwy {kind}.',
  'xss.textOnly':
    'Dane {origin} trafiają do {sink} w atrybucie HTML, znaczniku albo skrypcie po funkcji, która tylko usuwa znaczniki. Cudzysłowy zostają w wartości, więc może ona wyjść poza atrybut. Grozi {kind}.',
  'xss.textOnly.viaVar':
    'Zmienna {var} zawiera dane {origin} i trafia do {sink} w atrybucie HTML, znaczniku albo skrypcie po funkcji, która tylko usuwa znaczniki. Cudzysłowy zostają w wartości, więc może ona wyjść poza atrybut. Możliwy {kind}.',
  'xss.risk.stored': 'zapisanym XSS',
  'xss.risk.reflected': 'odbitym XSS',
  'xss.possible.stored': 'zapisany XSS',
  'xss.possible.reflected': 'odbity XSS',
  'xss.sink.echo': 'echo lub print',
  'xss.sink.exit': 'die lub exit',
  'xss.sink.shortcode': 'zwracanego HTML shortcode',
  'xss.sink.printf': 'printf',
  'xss.sink.wp_die': 'wp_die',
  'xss.sink.html': 'tekstu HTML składanego w kodzie',
  'xss.sink.do_shortcode': 'wywołania do_shortcode',
  'xss.patch.complete': 'Opakuj dane w {names}.',
  'xss.patch.manual':
    'Opakuj dane w {names}. Kontekst HTML nie wynika z kodu, więc sprawdź, czy to właściwa funkcja.',
  'join.and': ' i ',

  // Wykonanie kodu i poleceń.
  'rce.from.direct': 'od użytkownika',
  'rce.from.viaVar': 'ze zmiennej {var} zasilonej danymi {origin}',
  'rce.eval.message': 'eval wykonuje kod zbudowany dynamicznie. To prosta droga do zdalnego wykonania kodu.',
  'rce.eval.fix': 'Usuń eval. Zbuduj logikę wprost w PHP, bez wykonywania tekstu jako kodu.',
  'rce.include.message':
    'include lub require ze ścieżką {from}. Grozi dołączeniem obcego pliku i wykonaniem kodu.',
  'rce.include.fix':
    'Nie buduj ścieżki z danych wejściowych. Użyj stałej listy dozwolonych plików (allowlista) albo ścieżek względem katalogu wtyczki.',
  'rce.template.message':
    '{name}() ładuje szablon o nazwie zbudowanej {from}. Nazwa z ../ może dołączyć plik PHP spoza katalogu szablonów.',
  'rce.template.fix':
    'Przypisz dozwolone nazwy szablonów do stałych plików i odrzucaj resztę. Nie przekazuj danych wejściowych wprost do funkcji ładującej szablon.',
  'rce.backtick.message': 'Polecenie w backtickach {from}. Grozi wstrzyknięciem polecenia systemowego.',
  'rce.shell.message': '{name}() uruchamia polecenie {from}. Grozi wstrzyknięciem polecenia systemowego.',
  'rce.shell.fix':
    'Unikaj powłoki. Jeśli musisz, przekaż argumenty przez escapeshellarg i nie sklejaj ich w tekst polecenia.',

  // Reguły ujść: pliki, adresy HTTP, wysyłanie plików, role i opcje.
  'from.direct': 'od użytkownika',
  'from.viaVar': 'ze zmiennej {var} zasilonej danymi {origin}',
  'file.read.message':
    '{name}() czyta plik spod ścieżki {from}. Atakujący może odczytać pliki takie jak wp-config.php.',
  'file.write.message':
    '{name}() zapisuje plik pod ścieżką {from}. Atakujący może nadpisać pliki albo podrzucić kod PHP.',
  'file.delete.message':
    '{name}() usuwa plik spod ścieżki {from}. Atakujący może usunąć pliki takie jak wp-config.php i przejąć witrynę.',
  'file.fix':
    'Nie buduj ścieżki z danych wejściowych. Przypisz dozwolone nazwy do stałych plików albo zredukuj dane do nazwy pliku przez wp_basename() i sprawdź, że realpath() leży w oczekiwanym katalogu.',
  'ssrf.message':
    '{name}() wysyła żądanie pod adres {from}. Atakujący może skierować serwer do usług wewnętrznych albo obcych hostów.',
  'ssrf.fix':
    'Nie bierz adresu z danych wejściowych. Użyj stałego adresu albo sprawdź host na liście dozwolonych. wp_safe_remote_get() odrzuca adresy wewnętrzne, a wp_http_validate_url() sprawdza adres.',
  'upload.move.message':
    'move_uploaded_file() zapisuje plik pod nazwą {from}, a nic w tej funkcji nie sprawdza typu pliku. Atakujący może wysłać skrypt PHP i uruchomić kod.',
  'upload.notype.message':
    '{name}() działa z wyłączonym sprawdzaniem typu pliku (test_type ustawione na false). Atakujący może wysłać skrypt PHP i uruchomić kod.',
  'upload.fix':
    'Sprawdź rozszerzenie i typ na liście dozwolonych przez wp_check_filetype_and_ext(), nazwę pliku nadaj sam (wp_unique_filename()) i nie zapisuj wysłanych plików tam, gdzie serwer wykonuje PHP.',
  'privilege.role.message':
    'Rola konta jest ustawiana wartością {from}. Atakujący może nadać sobie rolę administratora.',
  'privilege.setrole.message':
    '{name} ustawia rolę wartością {from}. Atakujący może nadać sobie rolę administratora.',
  'privilege.userdata.message':
    '{name}() dostaje całe żądanie jako dane konta, więc żądanie ustawia też rolę. Atakujący może utworzyć konto administratora.',
  'privilege.meta.message':
    '{name}() zapisuje meta użytkownika pod kluczem {from}. Atakujący może zapisać klucz wp_capabilities i zostać administratorem.',
  'privilege.caps.message':
    '{name}() zapisuje uprawnienia konta wartością {from}. Atakujący może nadać sobie dowolne uprawnienia.',
  'privilege.login.message':
    '{name}() loguje konto o identyfikatorze {from}. Nic w tej funkcji nie dowodzi, kim jest odwiedzający. Atakujący może zalogować się jako dowolny użytkownik, także administrator.',
  'privilege.role.fix':
    'Nie bierz roli z żądania. Ustaw stałą rolę (na przykład subscriber), a wybór roli zostaw użytkownikom z uprawnieniem promote_users.',
  'privilege.meta.fix':
    'Użyj stałego klucza albo listy dozwolonych kluczy. Nie pozwól, żeby żądanie wybierało klucz, który może być wp_capabilities lub wp_user_level.',
  'privilege.login.fix':
    'Loguj konto dopiero po udowodnieniu tożsamości, na przykład sprawdzeniem hasła, jednorazowym tokenem porównanym przez hash_equals() albo podpisanym linkiem. Nie ufaj identyfikatorowi użytkownika z żądania.',
  'option.update.message':
    '{name}() zmienia opcję o nazwie {from}. Atakujący może zmienić ustawienia takie jak default_role albo users_can_register i przejąć witrynę.',
  'option.delete.message':
    '{name}() usuwa opcję o nazwie {from}. Atakujący może usunąć opcje rdzenia i zepsuć witrynę.',
  'option.fix':
    'Nie bierz nazwy opcji z danych wejściowych. Użyj stałej nazwy albo sprawdź ją na liście własnych opcji i wymagaj uprawnienia, na przykład manage_options.',

  // Deserializacja.
  'unserialize.full': '{name}() na danych z superglobala. Grozi wstrzyknięciem obiektu PHP (object injection).',
  'unserialize.limited':
    '{name}() na danych z superglobala z ograniczoną listą klas. Sprawdź, czy żadna z nich nie ma metod magicznych, które można nadużyć.',
  'unserialize.viaVar': '{name}() na zmiennej {var}, która zawiera dane {origin}. Możliwe wstrzyknięcie obiektu PHP (object injection).',
  'unserialize.viaVar.limited':
    '{name}() na zmiennej {var}, która zawiera dane {origin}, z ograniczoną listą klas. Sprawdź, czy żadna z nich nie ma metod magicznych, które można nadużyć.',
  'unserialize.fix':
    'Nie deserializuj danych od użytkownika. Użyj json_decode z danymi JSON, a jeśli musisz, wymuś allowed_classes => false.',
  'unserialize.patch': 'Zablokuj tworzenie obiektów: dodaj allowed_classes => false.',

  // Opcje.
  'registerSetting.message': 'register_setting bez sanitize_callback. Wartość opcji jest zapisywana bez walidacji.',
  'registerSetting.fix':
    'Dodaj sanitize_callback w tablicy argumentów register_setting, np. sanitize_text_field albo własną walidację pod typ opcji.',

  // Trasy REST.
  'rest.missing.message':
    'register_rest_route bez permission_callback. Endpoint REST jest dostępny bez kontroli uprawnień.',
  'rest.missing.fix':
    'Dodaj permission_callback i sprawdź uprawnienia, np. current_user_can albo weryfikację nonce. Dla endpointu celowo publicznego ustaw to świadomie.',
  'rest.openWrite.message':
    'permission_callback ustawiony na __return_true na trasie zmieniającej dane. Endpoint REST jest otwarty dla każdego.',
  'rest.openWrite.fix':
    'Jeśli endpoint ma być publiczny, zostaw to świadomie. W innym wypadku sprawdź uprawnienia przez current_user_can albo weryfikację nonce.',

  // Sekrety.
  'secret.label.aws': 'klucz dostępu AWS',
  'secret.label.stripe': 'klucz Stripe (live)',
  'secret.label.github': 'token GitHub',
  'secret.label.google': 'klucz API Google',
  'secret.label.slack': 'token Slack',
  'secret.label.privateKey': 'klucz prywatny',
  'secret.label.sendgrid': 'klucz API SendGrid',
  'secret.note.google':
    'Klucz do map w przeglądarce bywa publiczny z założenia, ale ten sam format mają klucze płatnych API. Sprawdź w konsoli Google, czy klucz ma ograniczenia.',
  'secret.provider': 'Wykryto {label} zaszyty w kodzie.',
  'secret.byName': 'Wartość przypisana do "{name}" wygląda na zaszyty sekret.',
  'secret.fix':
    'Przenieś sekret poza kod, do zmiennej środowiskowej albo do wp-config.php poza repozytorium. Jeśli trafił do repo, rotuj go.',

  // Nonce i uprawnienia.
  'auth.nonce.message': 'Uchwyt haka "{hook}" nie weryfikuje nonce. Grozi CSRF.',
  'auth.nonce.fix':
    'Dodaj check_admin_referer lub check_ajax_referer na początku uchwytu, a w formularzu pole wp_nonce_field.',
  'auth.capability.message':
    'Uchwyt haka "{hook}" nie sprawdza uprawnień użytkownika. Grozi nieautoryzowanym działaniem.',
  'auth.capability.fix':
    'Dodaj current_user_can z właściwą zdolnością na początku uchwytu i przerwij, gdy brak uprawnień.',

  // Silnik i kolektor.
  'error.tooDeep': 'plik zbyt głęboko zagnieżdżony, pominięto',
  'error.parse': 'błąd parsowania: {detail}',
  'error.rule': 'reguła {rule}: {detail}',
  'error.read': 'nie udało się odczytać pliku: {detail}',
  'git.notRepo': 'katalog nie jest repozytorium git, tryb --diff wymaga gita',
  'git.diffFailed': 'git diff nie powiodło się dla punktu odniesienia "{ref}"',

  // Raport w terminalu.
  'severity.critical': 'KRYTYCZNE',
  'severity.high': 'WYSOKIE',
  'severity.medium': 'ŚREDNIE',
  'severity.low': 'NISKIE',
  'severity.info': 'INFO',
  'report.title': 'WPCoderScan  skan: {target}',
  'report.counts': 'plików: {files}, znalezisk: {findings}',
  'report.heuristic': 'heurystyka',
  'report.fix': 'naprawa: {text}',
  'report.suggestion': 'podpowiedź: {label}',
  'report.suggestion.manual': 'podpowiedź (do decyzji): {label}',
  'report.score': 'Wynik: {value}/100',
  'report.count.critical': 'krytyczne {n}',
  'report.count.high': 'wysokie {n}',
  'report.count.medium': 'średnie {n}',
  'report.count.low': 'niskie {n}',
  'report.errors': 'błędy skanera: {count}',
  'report.patchHint': 'podpowiedzi napraw: {count} (pokaż je opcją --suggest)',
  'report.suppressed': 'wyciszone komentarzem: {count}',
  'report.baselined': 'w baseline: {count}',
  'report.warnings': 'ostrzeżenia: {count}',
  'report.staleBaseline': 'wpisy baseline bez dopasowania: {count} (odśwież plik opcją --write-baseline)',

  // Komentarze wyciszające, plik ustawień i baseline.
  'warn.ignoreNoRule': 'wpcoderscan-ignore wymaga identyfikatora reguły, komentarz pominięto',
  'warn.ignoreUnknownRule': 'wpcoderscan-ignore: "{rule}" nie pasuje do żadnej reguły',
  'config.notFound': 'nie znaleziono pliku ustawień: {file}',
  'config.invalid': 'nie da się użyć pliku ustawień {file}: {detail}',
  'config.expectedObject': 'na najwyższym poziomie musi być obiekt JSON',
  'config.unknownKey': '{file}: nieznana opcja "{key}"',
  'config.badType': '{file}: opcja "{key}" ma zły typ, oczekiwano {expected}',
  'config.badRuleValue': '{file}: reguła "{rule}" w "rules" może mieć tylko wartość "off"',
  'config.unknownRule': '{file}: "rules" wymienia "{rule}", a to nie jest reguła',
  'config.badLang': '{file}: nieznany język "{value}" w "lang", obsługiwane języki: {supported}',
  'config.using': 'używam ustawień z {file}',
  'baseline.notFound': 'nie znaleziono pliku baseline: {file}',
  'baseline.invalid': 'plik baseline jest nieprawidłowy. Utwórz go ponownie opcją --write-baseline',
  'baseline.saved': 'Zapisano baseline w {file}: znalezisk {count}. Od teraz zgłaszamy tylko nowe znaleziska.',

  // CLI.
  'cli.help': `WPCoderScan - skaner bezpieczeństwa kodu WordPress i PHP

Użycie:
  wpcoderscan <ścieżka> [opcje]

Opcje:
  --json              wypisz wynik jako JSON
  --sarif             wypisz wynik jako SARIF 2.1.0 (do zakładki Security GitHuba)
  --fail-on <poziom>  kod wyjścia 1, gdy jest znalezisko tego poziomu lub cięższe
                      (critical, high, medium, low, none; domyślnie high)
  --strict            licz też znaleziska heurystyczne do kodu wyjścia
                      (domyślnie build łamią tylko znaleziska pewne)
  --diff <ref>        skanuj tylko pliki PHP zmienione wobec ref gita
                      (domyślnie HEAD; szybki skan dla pull requestów)
  --extended          dołącz reguły rozszerzone (większa czułość, więcej fałszywych alarmów)
  --suggest           pokaż podpowiedzi napraw przy znaleziskach (nic nie zapisuje)
  --patch <plik>      zapisz pełne podpowiedzi napraw jako łatkę do git apply
  --baseline <plik>   ukryj znaleziska zapisane w baseline, zgłaszaj tylko nowe
  --write-baseline <plik>
                      zapisz bieżące znaleziska jako baseline i zakończ kodem 0
  --config <plik>     wczytaj ustawienia z pliku
                      (domyślnie .wpcoderscan.json w bieżącym katalogu)
  --no-config         nie czytaj pliku ustawień
  --no-ignore-comments
                      nie honoruj komentarzy wpcoderscan-ignore w skanowanym kodzie
  --lang <en|pl>      język wyjścia (domyślnie en; także zmienna WPCODERSCAN_LANG)
  -v, --version       pokaż wersję
  -h, --help          ta pomoc
`,
  'cli.error': 'błąd: {message}',
  'cli.patch.none': 'Brak pełnych podpowiedzi napraw, łatka nie powstała.',
  'cli.patch.saved': 'Zapisano łatkę {file}: poprawek {patches}, plików {files}.',
  'cli.patch.apply': 'Sprawdź ją i zastosuj: git apply --check {file} && git apply {file}',
  'cli.patch.manual': 'Pominięto {count} podpowiedzi do decyzji. Zobacz je opcją --suggest.',
  'cli.warning': 'ostrzeżenie: {message}',
  'cli.missingValue': 'opcja {option} wymaga wartości',
  'cli.baselineDiff': '--write-baseline nie działa razem z --diff, bo baseline objąłby tylko zmienione pliki',
  'cli.badFailOn': 'nieznany poziom --fail-on "{value}", użyj critical, high, medium, low albo none',
};
