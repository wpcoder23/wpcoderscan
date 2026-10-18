# Historia zmian

## 0.1.0

Pierwsze wydanie publiczne.

- Osiem reguł: SQL injection, trasy REST bez kontroli dostępu, RCE, `unserialize`, `register_setting`, zaszyte sekrety, XSS w `echo` i `print`, uchwyty akcji bez nonce i uprawnień.
- Lekka analiza skażenia danych w obrębie funkcji. Zmienna zasilona superglobalem jest śledzona, rzutowania i funkcje czyszczące zdejmują skażenie.
- Poziom pewności znaleziska: pewne łamią build, heurystyki tylko ostrzegają. Flaga `--strict` liczy też heurystyki.
- Raporty: terminal, JSON i SARIF 2.1.0.
- Tryb `--diff <ref>` do szybkiego skanu zmian w pull requestach.
- Akcja GitHub (composite) budowana ze źródeł repozytorium.
- Walidacja na 253 realnych wtyczkach i motywach WordPress: 0 awarii, około 42 tysiące plików PHP.
