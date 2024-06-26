## IZVESTAJ

Zadatak je zahtevao da iskoristimo vulnerability u Tar biblioteci, koji ima unsafe unzipping fajlova.
Do te ranjivosti dolazi zato sto biblioteka ne versi validaciju putanje fajlova kada ih ekstrahuje iz neke arhive. Time je omoguceno da u putanjama fajlova mozemo da zadamo relativne putanje koje ne bi smele biti dostupne. Kako bismo to postigli, mozemo promeniti path na putanje poput:
    - ../../file.txt cime mozemo postici da se taj fajl sacuva u jednom od roditeljskih foldera umesto u namenjenom.

Pre pokretanja app.py, potrebno je izvrsiti helper.py skriptu koja ce da zapakuje nas "maliciozni" fajl u .tar arhivu. Posle toga mozemo pokrenuti app.py i otici na localhost:5000.

Uploadujemo nasu novokreiranu arhivu .tar i ako je upload bio uspesan (ako postoji fajl u uploads folderu projekta), pogledamo u 3 parent foldera iznad namenjenog uploads foldera. Ako pronadjemo tu sada nas malicious fajl, to znaci da smo uspesno iskoristili ranjivost. 