<?php
// Ucieczka zależna od kontekstu.
echo esc_html( $_GET['name'] );
print esc_attr( $_POST['message'] );
echo esc_url( $_GET['redirect'] );

// Rzutowanie liczbowe neutralizuje wejście.
echo (int) $_GET['page'];

// Sanitizacja pola tekstowego.
echo sanitize_text_field( $_REQUEST['q'] );

// Dozwolone tagi przez wp_kses.
echo wp_kses_post( $_POST['content'] );

// Czysty literał bez danych użytkownika.
echo 'Zwykły tekst strony';

// Pełna nazwa funkcji z wiodącym ukośnikiem.
echo \esc_html( $_GET['name'] );

// Superglobal tylko w warunku, nie w wyniku.
echo isset( $_GET['x'] ) ? 'tak' : 'nie';
echo ! empty( $_GET['y'] ) ? 'jest' : 'brak';

// Superglobal jako klucz, nieznana funkcja i wynik porównania.
echo $labels[ $_GET['type'] ];
echo my_theme_label( $_GET['type'] );
echo $_GET['a'] === 'b' ? 'b' : 'inne';

// Zmienna oczyszczona przed wypisaniem i zmienna lokalna.
$q = sanitize_text_field( $_GET['q'] );
echo $q;
$title = get_the_title();
echo $title;
echo $_SERVER['REQUEST_TIME'];
