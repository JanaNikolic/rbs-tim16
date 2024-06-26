# Izveštaj Spring Boot aplikacije

## 1. Opis projekta
Projektni zadatak je kreiranje aplikacije za naručivanje prevoza nalik na aplikaciju za Uber. Aplikacija je sačinjena od backend aplikacije koja je kreira u Spring Boot radnom okviru i komunicira sa frontend i mobilnim dijelom aplikacije. U ovoj analizi je fokus na backend dijelu aplikacije.

## 2. Članovi razvojnog tima
- Srđan Stjepanović
- Nemanja Vujadinović
- Tina Mihajlović

## 3. Pronađeni defekti
Korišćenjem checkstyle alata izvršena je analiza koda, čije greške se uglavnom odnose na stil pisanja samog koda. Greške koje treba istaći su:
1.  Pozivanje metode Throwable.printStackTrace() bez argumenata kao i zakomentarisan java kod 
2.  Upotreba deprecated klasa i metoda
3.  Nullability i problem toka podataka
4.  Optional.get() metoda je pozvana bez prethodnog poziva isPresent() što može izazvati izuzetak
5.  Zanemarivanje standardnih konevencija za pisanje koda

Zatim je pokrenut OWASP Dependency Check kako bi se otkrile javno poznate ranjivosti. Izvještaj analize se nalazi na sledećem [linku](dependency-check-report.html) u kojem se mogu vidjeti otkrivene ranjivosti, nivo opasnosti, CVE identifikator, komponente koje su ranjive kao i predlog za rešenje ranjivosti.

## 4. Preporuke kako bi se kod poboljšao

- **Brisanje zakomentarisanog koda**: Brisanje zakomentarisanog koda koji se ne koristi i koji će vjerovatno postati outdated, takođe se preporučuje brisanje nepotrebnih linija koda koje su korištene u procesu debagovanja. 

- **Izbjegavanje korištenja deprecated API-a**: ovim naš kod ostaje održiv, siguran i kompatibilan sa budućim verzijama biblioteka

- **Koristiti @NonNull anotacije** treba izbjegavati vraćanje null vrijednosti iz funkcije, a ukoliko je rad sa null vrijednostima neizbežan koristiti provjeru

- **Pratiti konvencije za pisanje koda** izbjegavati nepotrebno pisanje modifier-a, eksplicitno navodjenje tipa se može zamijeniti sa "<>", upotreba lambda funkcija itd.

Za analizu koda bilo je potrebno 1h i 30 min.


