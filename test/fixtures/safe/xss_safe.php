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
