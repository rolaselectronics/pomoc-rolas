# Pomoc Rolas

Jednoplikowy klient pomocy zdalnej dla Rolas Electronics. Program pokazuje
losowy sześciocyfrowy identyfikator i zestawia wychodzące połączenie z
repeaterem UltraVNC Mode II pod adresem `servis.rolas.com.pl:5500`.

## Właściwości

- domyślnie działa jako jednorazowa sesja bez instalacji;
- nie otwiera lokalnego portu nasłuchującego VNC;
- kończy dostęp po zamknięciu okna;
- usuwa rozpakowane pliki tymczasowe po zakończeniu;
- szyfruje połączenie przez SecureVNCPlugin;
- używa niezmodyfikowanych binariów UltraVNC 1.8.2.4 dla x86 i x64.

## Stały dostęp (od wersji 1.1.1)

Przycisk **Włącz stały dostęp** instaluje, po potwierdzeniu UAC, usługę UltraVNC
uruchamianą automatycznie z Windows. Usługa zachowuje wyświetlony sześciocyfrowy
identyfikator również po restarcie i działa przed zalogowaniem użytkownika.

Po zalogowaniu widoczna jest ikona Pomoc Rolas obok zegara. Dwukrotne kliknięcie
pokazuje zapisane ID, a menu ikony umożliwia jawne usunięcie stałego dostępu.
Instalacja ani usunięcie usługi nie odbywa się bez zgody administratora.

## Budowanie

Wymagane są Zig oraz OpenSSL. Prawdziwego hasła nie ma w repozytorium.
Podaje się je wyłącznie na czas budowania:

```bash
ROLAS_ACCESS_PASSWORD='TU_WPISZ_HASLO' ./build.sh
```

Hasło może mieć od 1 do 8 znaków ASCII. Skrypt tworzy tymczasowy nagłówek,
buduje `dist/Pomoc-Rolas-1.1.1.exe`, a następnie usuwa nagłówek. W GitHub
Actions hasło jest pobierane z tajnego ustawienia `ROLAS_ACCESS_PASSWORD`.

## Bezpieczeństwo

Klient wymaga świadomego uruchomienia przez użytkownika i wyraźnie pokazuje
identyfikator sesji. Jednorazowy dostęp trwa do zamknięcia programu. Stały dostęp
jest włączany i usuwany wyłącznie przez jawne działania wymagające uprawnień
administratora. Zasady zgłaszania problemów opisuje plik `SECURITY.md`.

## Code signing policy

Free code signing provided by [SignPath.io](https://signpath.io/), certificate by
[SignPath Foundation](https://signpath.org/).

- Committer and reviewer: [Michał Rdzonek (@rolaselectronics)](https://github.com/rolaselectronics)
- Approver: [Michał Rdzonek (@rolaselectronics)](https://github.com/rolaselectronics)
- Privacy: program nie wysyła telemetrii. Łączy się wyłącznie ze wskazanym
  repeaterem `servis.rolas.com.pl`, gdy użytkownik uruchomi sesję pomocy albo
  świadomie włączy stały dostęp.

## Licencja

Cały projekt jest udostępniany na licencji GPL-3.0-or-later. Informacje o
UltraVNC i odpowiadającym kodzie źródłowym znajdują się w
`THIRD_PARTY_NOTICES.txt`.
