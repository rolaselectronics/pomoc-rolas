# Pomoc Rolas

Jednoplikowy klient pomocy zdalnej dla Rolas Electronics. Program pokazuje
losowy sześciocyfrowy identyfikator i zestawia wychodzące połączenie z
repeaterem UltraVNC Mode II pod adresem `servis.rolas.com.pl:5500`.

## Właściwości

- nie instaluje usługi ani autostartu;
- nie otwiera lokalnego portu nasłuchującego VNC;
- kończy dostęp po zamknięciu okna;
- usuwa rozpakowane pliki tymczasowe po zakończeniu;
- szyfruje połączenie przez SecureVNCPlugin;
- używa niezmodyfikowanych binariów UltraVNC 1.8.2.4 dla x86 i x64.

## Budowanie

Wymagane są Zig oraz OpenSSL. Prawdziwego hasła nie ma w repozytorium.
Podaje się je wyłącznie na czas budowania:

```bash
ROLAS_ACCESS_PASSWORD='TU_WPISZ_HASLO' ./build.sh
```

Hasło może mieć od 1 do 8 znaków ASCII. Skrypt tworzy tymczasowy nagłówek,
buduje `dist/Pomoc-Rolas-1.0.6.exe`, a następnie usuwa nagłówek. W GitHub
Actions hasło jest pobierane z tajnego ustawienia `ROLAS_ACCESS_PASSWORD`.

## Bezpieczeństwo

Klient wymaga świadomego uruchomienia przez użytkownika, wyraźnie pokazuje
identyfikator sesji i nie ukrywa działającego okna. Dostęp trwa wyłącznie do
zamknięcia programu. Zasady zgłaszania problemów opisuje plik `SECURITY.md`.

## Licencja

Cały projekt jest udostępniany na licencji GPL-3.0-or-later. Informacje o
UltraVNC i odpowiadającym kodzie źródłowym znajdują się w
`THIRD_PARTY_NOTICES.txt`.
