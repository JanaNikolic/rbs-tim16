# Autor
Srdjan Stjepanovic SV16/2020

# Penetration testing

U ovom zadatku je kreirana aplikacija koja posjeduje poznatu ranjivost CVE-2007-4559 i zatim se eksploatisala ta ranjivost.

# CVE-2007-4559

Ova ranjivost predstavlja ranjivost koja se odnosi na modul "tarfile" iz Python standardne biblioteke. Ona omogucava napadacu da iyvrsi proiyvoljni kod putem directory traversal napada kada se .tar file dekompresuje. To dovodi do smestanja raspakovanih fajlova izvan predvidjenog foldera.

# Eksploatacija

Prvo je kreirana flask web aplikacija, koja posjeduje polje za upload fajlova. Nakon sto korisnik submituje fajl, aplikacija ekstrakuje arhivu na server. Potom kreiramo tar arhivu koja posjeduje fajlove sa relativnim putanjama koje ce iskoristiti za pristup drugim folderima. U nasem slucaju u tar arhivu stavljamo malicious_index.html, a prilikom arhiviranja tom fajlu stavljamo ime na ../templates/index.html. Time omogucavamo da malicious_index.html zamijeni pravi index.html koji koristi aplikacija. Kada upload-ujemo na server, automatski ce se izvrsiti zamjena html fajlova. 

# Zakljucak

Nasa aplikacija nema validaciju putanja fajlova koji su ekstrakovani iz tar arhive, sto dovodi da fajlovi sa relativnim putanjama mogu da dodju do otkrivanja informacija i promjene sistema. Mjere zastite bi bila da se validira putanja svakog fajla kako bi se utvrdilo da putanja ne pokusava Path Traversal napad, takodje ekstrakovanje arhiva bi se moglo vrsiti sa ogranicenim privilegijama, kako bi minimalizovali potencijalnu stetu.