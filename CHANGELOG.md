# Historia zmian

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
