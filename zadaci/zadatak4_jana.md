# Izveštaj mobline aplikacije

## 1. Opis projekta
    
Projektni zadatak je stvaranje mobilne aplikacije koja omogućava korisnicima da zakažu prevoz na način sličan Uberu. Cilj je olakšati korisnicima transport uz manje interakcije s vozačem, što bi trebalo ubrzati proces, učiniti ga doslednijim i sigurnijim, imajući u vidu nedostatke sadašnjeg sistema taksi prevoza.

## 2. Članovi razvojnog tima

- Katarina Mirković
- Jana Nikolić
- Bogdan Janošević

## 3. Pronađeni defekti

Korišćenjem Mairiana Trench alata za statičku analizu Java koda, otkriveno je 13 issue-a. Svaki od njih se odnosi na problem implicitnog rukovanja Intent-a rezličitih paketa.
1.  Prvi problem sugeriše potencijalnu bezbednosnu ranjivost u Android aplikaciji u vezi sa implicitnim rukovanjem Intent-a u klasi GenericIdpActiviti iz com/google/firebase/auth/internal paketa.
2. Implicitno rukovanje intent u NavController klasi iz androidx.navigation paketa
3. Implicitno rukovanje intent u ActivityNavigator klasi iz androidx.navigation paketa
4. Implicitno rukovanje intent u GoogleApiManager klasi iz com.google.android.gms.common.api.internal paketa
5. Čuvanje JWT tokena u okviru SharedPreferences
6. Nedostatak validacije input polja i sprovođenje zahteva za korišćenje složenih lozinki
7. Mrežna kominikacija preko HTTP protokola

## 4. Preporuke kako bi se kod poboljšao

- **Pregled rukovanja implicitnim namerama**: Ispitati kako se rukuje implicitnim namerama unutar klasa. Proveriti da su svi podaci primljeni putem implicitnih namera pravilno validirani, očišćeni i verifikovani pre upotrebe da bi sprečili potencijalne bezbednosne propuste kao što su ubrizgavanje namere ili eskalacija privilegija.
- **Validirati izvore podataka**: Pregledati izvore podataka koji teku u metodu onResume() da bi identifikovali sve izvore koje kontrolišu third-party biblioteke. Proceniti da li se ovim izvorima može verovati i da li je neophodna dodatna provera valjanosti ili filtriranje da bi se obezbedio integritet i bezbednost podataka.
-   **Bezbedno rukovanje namerom**: Sprovesti odgovarajuće mere bezbednosti, kao što je rukovanje eksplicitnom namerom ili eksplicitna provera valjanosti podataka, kako bi ublažili rizik od neovlašćenog pristupa podacima ili nenamernog ponašanja koje je rezultat rukovanja implicitnom namerom.
- **Pratiti best practices za Android bezbednost**: Pridržavanje najboljim bezbednosnim praksama i smernica za Android koje je obezbedio Google kako bi obezbedili opštu bezbednost i integritet svoje Android aplikacije.
- **Korišćenje secure storage-a za čuvanje osetljivih podataka**: Osetljivi podaci, kao što je JWT, potrrebno je čuvati u nekom od bezbednih skladišta kao što je Android Keystore
- **Validacija input polja**: Adekvatna validacija korisniških unosa je neophodno kako bi se zaštitili od raznih napada kao sto su injection napadi.
- **Bezbedna mrežna komunikacija**:  Sva mrežna komunikacija bi trebala biti zaštićena pomoću HTTPS protokola kako bi zaštitili podatke koji se prenose između aplikacije i servera.

Za ručni pregled koda bilo je potrebno dva sata i pronađena su tri defekta.