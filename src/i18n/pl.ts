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

  // Pochodzenie danych.
  'origin.request': 'z żądania REST',
  'origin.url': 'z adresu bieżącej strony (add_query_arg bez adresu)',
  'origin.param': 'z parametru funkcji',
  'origin.shortcode': 'z atrybutów shortcode',
  'origin.user': 'od użytkownika',

  // SQL injection.
  'sqli.fix':
    'Użyj $wpdb->prepare() z placeholderami %s, %d, %f i przekaż dane jako argumenty, zamiast sklejać je w tekst zapytania.',
  'sqli.direct': 'Wywołanie $wpdb->{method}() wkleja dane od użytkownika do zapytania bez prepare. Grozi SQL injection.',
  'sqli.viaVar':
    'Wywołanie $wpdb->{method}() używa zmiennej {var}, która zawiera dane {origin}, i buduje z niej zapytanie bez prepare. Prawdopodobny SQL injection.',
  'sqli.param.message':
    'Wywołanie $wpdb->{method}() buduje zapytanie z parametru {var} funkcji bez prepare. Jeśli do funkcji trafiają dane od użytkownika, grozi SQL injection.',
  'sqli.param.fix':
    'Użyj $wpdb->prepare() z placeholderami, a dla liczb rzutuj na int albo absint. Nazwy kolumn i kierunek sortowania sprawdź na liście dozwolonych wartości.',

  // XSS.
  'xss.fix':
    'Opakuj dane funkcją ucieczki zależną od kontekstu: esc_html w treści, esc_attr w atrybucie, esc_url w adresie. Dla HTML z tagami użyj wp_kses_post.',
  'xss.direct': 'Dane {origin} trafiają do {sink} bez funkcji ucieczki. Grozi {kind}.',
  'xss.viaVar': 'Zmienna {var} zawiera dane {origin} i trafia do {sink} bez funkcji ucieczki. Możliwy {kind}.',
  'xss.risk.stored': 'zapisanym XSS',
  'xss.risk.reflected': 'odbitym XSS',
  'xss.possible.stored': 'zapisany XSS',
  'xss.possible.reflected': 'odbity XSS',
  'xss.sink.echo': 'echo lub print',
  'xss.sink.exit': 'die lub exit',
  'xss.sink.shortcode': 'zwracanego HTML shortcode',
  'xss.sink.printf': 'printf',
  'xss.sink.wp_die': 'wp_die',
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
  'rce.backtick.message': 'Polecenie w backtickach {from}. Grozi wstrzyknięciem polecenia systemowego.',
  'rce.shell.message': '{name}() uruchamia polecenie {from}. Grozi wstrzyknięciem polecenia systemowego.',
  'rce.shell.fix':
    'Unikaj powłoki. Jeśli musisz, przekaż argumenty przez escapeshellarg i nie sklejaj ich w tekst polecenia.',

  // Deserializacja.
  'unserialize.full': '{name}() na danych z superglobala. Grozi wstrzyknięciem obiektu PHP (object injection).',
  'unserialize.limited':
    '{name}() na danych z superglobala z ograniczoną listą klas. Sprawdź, czy żadna z nich nie ma metod magicznych, które można nadużyć.',
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
  --lang <en|pl>      język wyjścia (domyślnie en; także zmienna WPCODERSCAN_LANG)
  -v, --version       pokaż wersję
  -h, --help          ta pomoc
`,
  'cli.error': 'błąd: {message}',
  'cli.patch.none': 'Brak pełnych podpowiedzi napraw, łatka nie powstała.',
  'cli.patch.saved': 'Zapisano łatkę {file}: poprawek {patches}, plików {files}.',
  'cli.patch.apply': 'Sprawdź ją i zastosuj: git apply --check {file} && git apply {file}',
  'cli.patch.manual': 'Pominięto {count} podpowiedzi do decyzji. Zobacz je opcją --suggest.',
  'cli.badFailOn': 'nieznany poziom --fail-on "{value}", użyj critical, high, medium, low albo none',
};
