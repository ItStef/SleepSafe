# SleepSafe — potpuno objašnjenje projekta

Ovaj dokument pretpostavlja da ne znaš ništa ni o sajber bezbednosti ni o ovim tehnologijama. Sve se objašnjava od nule, a zatim se, fajl po fajl, objašnjava tačno šta SleepSafe radi i zašto je napisan baš tako. Sve je tačno stanje koda u trenutku pisanja (grana `main`).

**Šta je SleepSafe u jednoj rečenici:** menadžer lozinki koji radi u pregledaču (kao veb sajt), gde server koji čuva podatke **nikad ne vidi** tvoje lozinke — sve što server dobija je već nečitljivo, šifrovano na tvom računaru pre nego što ikad napusti pregledač.

---

## Sadržaj

1. [Osnovni pojmovi sajber bezbednosti](#1-osnovni-pojmovi-sajber-bezbednosti)
2. [Osnove kriptografije](#2-osnove-kriptografije)
3. [Osnove veb bezbednosti](#3-osnove-veb-bezbednosti)
4. [Tehnologije korišćene u projektu](#4-tehnologije-korišćene-u-projektu)
5. [Arhitektura — kako su delovi povezani](#5-arhitektura--kako-su-delovi-povezani)
6. [`packages/crypto` — kriptografsko jezgro](#6-packagescrypto--kriptografsko-jezgro)
7. [`packages/shared` — zajednička pravila](#7-packagesshared--zajednička-pravila)
8. [`apps/api` — server](#8-appsapi--server)
9. [`apps/web` — klijent (ono što vidiš u pregledaču)](#9-appsweb--klijent-ono-što-vidiš-u-pregledaču)
10. [Infrastruktura, alati i podešavanja](#10-infrastruktura-alati-i-podešavanja)
11. [Tokovi kroz sistem, korak po korak](#11-tokovi-kroz-sistem-korak-po-korak)
12. [Šta se štiti i od koga (model pretnji)](#12-šta-se-štiti-i-od-koga-model-pretnji)
13. [Poznata ograničenja](#13-poznata-ograničenja)
14. [Rečnik pojmova](#14-rečnik-pojmova)

---

## 1. Osnovni pojmovi sajber bezbednosti

### 1.1 Šta uopšte znači "bezbedan sistem"

Kad se kaže da je neki softver bezbedan, obično se misli na tri svojstva, poznata kao **CIA trijada** (Confidentiality, Integrity, Availability):

- **Poverljivost (Confidentiality):** samo onaj ko treba da vidi podatak, taj ga i vidi. Tuđa lozinka ne sme biti čitljiva nikom drugom.
- **Integritet (Integrity):** podatak se ne sme neprimećeno izmeniti. Ako neko promeni tvoju sačuvanu lozinku u bazi, sistem to mora primetiti (ne sme tiho da prihvati izmenjen podatak kao ispravan).
- **Dostupnost (Availability):** sistem mora da radi kad ti zatreba. Napad koji obori server (npr. zatrpavanje zahtevima) napada baš ovo svojstvo.

Svaka bezbednosna mera u ovom projektu štiti jedno ili više od ova tri svojstva. Kroz dokument ćeš videti oznake poput "ovo štiti poverljivost" da se lakše poveže teorija sa kodom.

### 1.2 Autentikacija vs autorizacija

Ova dva pojma se lako mešaju:

- **Autentikacija** = dokazivanje ko si. ("Ja sam Marko, evo dokaza — znam lozinku Markovog naloga.")
- **Autorizacija** = provera da li smeš to da uradiš. ("Marko sme da vidi svoje stavke, ali ne i stavke drugog korisnika.")

SleepSafe radi autentikaciju kroz lozinku + email kod (poglavlje 8.7), a autorizaciju kroz to što server **uvek** uzima identitet korisnika iz proverene sesije, nikad iz onoga što klijent tvrdi da jeste (detaljno u 8.7 i 11).

### 1.3 Faktori autentikacije i 2FA

Postoje tri vrste "dokaza" da si to ti:

1. **Nešto što znaš** — lozinka, PIN.
2. **Nešto što imaš** — telefon, USB ključ, pristup email nalogu.
3. **Nešto što jesi** — otisak prsta, lice (biometrija).

**Dvofaktorska autentikacija (2FA)** znači da se traže dva different faktora iz dve različite kategorije. SleepSafe koristi lozinku (faktor 1) + kod poslat na email (faktor 2, "nešto što imaš" — pristup email nalogu). Ovo je opisano u 8.7 i 8.9.

### 1.4 Model pretnji i STRIDE

**Model pretnji (threat modeling)** je sistematsko razmišljanje: "Ko bi mogao da napadne ovaj sistem, na koji način, i šta bi se desilo?" Pre nego što se piše odbrana, prvo se popiše šta sve može da pođe naopako.

**STRIDE** je jedan od najpoznatijih okvira za to, sa šest kategorija pretnji (svaka napada jedno bezbednosno svojstvo):

| Slovo | Pretnja | Šta napada |
|---|---|---|
| S | Spoofing (lažno predstavljanje) | Autentičnost — neko se predstavlja kao neko drugi |
| T | Tampering (izmena) | Integritet — neko menja podatke koji nisu njegovi |
| R | Repudiation (poricanje) | Neporecivost — neko radi nešto i posle to poriče, a sistem nema dokaz |
| I | Information Disclosure (otkrivanje) | Poverljivost — neko vidi podatke koje ne bi trebalo |
| D | Denial of Service (uskraćivanje usluge) | Dostupnost — sistem prestaje da radi |
| E | Elevation of Privilege (podizanje privilegija) | Autorizacija — neko dobija veća prava nego što treba |

Puna primena STRIDE-a na ovaj projekat je u poglavlju 12.

### 1.5 Princip najmanjih privilegija i "defense in depth"

**Princip najmanjih privilegija:** svaki deo sistema treba da ima samo ona prava koja su mu neophodna, ništa više. U ovom projektu se to vidi u tome što server nikad ne dobija ključ kojim bi mogao da dešifruje tvoje podatke (nije mu ni potreban da bi radio svoj posao — čuvanje i sinhronizaciju).

**Odbrana u dubinu (defense in depth):** ne oslanjati se na samo jednu meru. Umesto da veruješ samo lozinci, dodaš i drugi faktor (email kod). Umesto da veruješ samo tome da je korisnik ko kaže da jeste, dodaš i proveru na nivou baze. Kroz projekat ćeš stalno viđati više slojeva zaštite koji se preklapaju.

---

## 2. Osnove kriptografije

Ovo poglavlje je najvažnije za razumevanje `packages/crypto`, srca ovog projekta.

### 2.1 Heš funkcija

**Heš funkcija** uzima bilo kakav ulaz (tekst, fajl, bilo šta) i pretvara ga u niz bajtova fiksne dužine ("otisak"). Ključna svojstva:

- **Jednosmerna je** — iz otiska se ne može rekonstruisati original.
- **Deterministička** — isti ulaz uvek daje isti izlaz.
- **Lavinski efekat** — i najmanja izmena ulaza (jedno slovo) potpuno menja izlaz.
- **Otporna na kolizije** — praktično nemoguće naći dva različita ulaza sa istim otiskom.

Projekat koristi **SHA-256** (izlaz od 32 bajta) kao osnovu za nekoliko drugih primitiva ispod.

**Bitno:** obična heš funkcija (SHA-256) **nije napravljena da bude spora**, pa nije dobra za heširanje lozinki direktno — napadač sa jakim računarom može da proba milijarde lozinki u sekundi. Zato postoji poseban tip funkcije, KDF (2.4).

### 2.2 MAC i HMAC

**MAC (Message Authentication Code)** je heš funkcija kojoj se, pored poruke, da i tajni ključ. Rezultat zavisi i od poruke i od ključa. Ko god nema ključ, ne može da izračuna ispravan MAC, pa MAC dokazuje dve stvari odjednom: da poruka nije menjana (integritet) i da je napravio neko ko zna tajnu (autentičnost).

**HMAC-SHA256** je standardna konstrukcija MAC-a nad SHA-256. Projekat je koristi na serveru za čuvanje "otisaka" tajni (Auth ključa, OTP koda, refresh tokena) — umesto da se sama tajna čuva u bazi, čuva se `HMAC(tajni_pepper, vrednost)`. Ako baza procuri, napadač vidi samo otiske, ne i same tajne, i bez `pepper`-a (koji je van baze, u `.env`) ne može da ih rekonstruiše niti proveri pogodak.

### 2.3 Salt i Pepper

Oba pojma su "dodatna so" koja se meša sa lozinkom pre heširanja, ali sa različitim namenama:

- **Salt** — nasumičan, **različit za svakog korisnika**, i **javno se čuva** (nije tajna) pored heša. Sprečava tzv. "rainbow table" napade: bez salt-a, dva korisnika sa istom lozinkom imali bi isti heš, pa bi napadač mogao unapred da izračuna tabelu čestih lozinki i njihovih heševa i da je koristi za sve naloge odjednom. Sa salt-om, svaki nalog efektivno ima svoju jedinstvenu "verziju" lozinke za heširanje.
- **Pepper** — jedna **tajna** vrednost, **ista za sve korisnike**, koja se **ne čuva u bazi** nego odvojeno (u ovom projektu, `.env` promenljiva `SERVER_PEPPER`). I ako cela baza procuri, napadač bez pepper-a ne može da proveri da li je pogodio pravu vrednost.

### 2.4 KDF (Key Derivation Function) — izvođenje ključa iz lozinke

Lozinka koju čovek pamti (npr. "MojaTajnaLozinka2024") nije dobar kriptografski ključ — prekratka je, nije nasumična, ljudi biraju predvidljive lozinke. **KDF** rešava ovo tako što lozinku pretvara u ključ fiksne dužine, i to **namerno sporo i memorijski zahtevno**, da bi napadaču koji pokušava da pogađa lozinku svaki pokušaj koštao vremena i resursa.

Projekat koristi **Argon2id** — pobednika Password Hashing Competition (2015) i trenutno preporučeni standard (OWASP, RFC 9106). Argon2id ima tri parametra kojima se kontroliše "cena" jednog pokušaja:

- **Memorija** (koliko MiB RAM-a mora da se zauzme) — ovo je najvažnije, jer sprečava napadača da paralelno pokreće milione pokušaja na specijalizovanom hardveru (GPU/ASIC), pošto svaki pokušaj troši dosta memorije.
- **Iteracije** — koliko puta se algoritam ponavlja.
- **Paralelizam** — koliko "traka" računa ide istovremeno.

Detaljni parametri i granice koje projekat koristi su u poglavlju 6.2.

### 2.5 Simetrična enkripcija i AEAD

**Simetrična enkripcija** znači da se isti ključ koristi i za šifrovanje i za dešifrovanje (za razliku od asimetrične, gde postoji par javni/privatni ključ — projekat je ne koristi direktno za podatke, samo posredno kroz TLS kad se doda HTTPS).

Projekat koristi **AES-256** (Advanced Encryption Standard, ključ od 256 bita) u modu **GCM (Galois/Counter Mode)**. GCM nije "obična" enkripcija — on je **AEAD (Authenticated Encryption with Associated Data)**, što znači da pored šifrovanja istovremeno daje i **integritet**: uz šifrat se generiše i "tag" (kao MAC), pa svaki pokušaj da se šifrat izmeni (i najmanje slovo) razbija tag i dešifrovanje eksplicitno puca, umesto da tiho vrati pogrešan/izmenjen tekst.

**IV (Initialization Vector)** je nasumičan broj koji se generiše za **svako pojedinačno šifrovanje**, čak i istim ključem. Bez njega, šifrovanje istog teksta istim ključem uvek bi dalo isti šifrat, što bi napadaču reklo "ove dve stavke imaju isti sadržaj", a u najgorem slučaju (ponovljen IV kod GCM-a) može doći do potpunog kompromitovanja ključa. Zato se IV **nikad ne sme ponoviti** za isti ključ — projekat ga generiše nasumično (CSPRNG, vidi 2.6) za svaku operaciju.

**AAD (Additional Authenticated Data)** je podatak koji se **ne šifruje**, ali **jeste** uključen u proveru integriteta (tag). Projekat ga koristi da "zalepi" šifrat za kontekst kome pripada — na primer, id korisnika i id stavke se ubacuju kao AAD, pa čak ni server (koji upravlja bazom) ne bi mogao da uzme šifrovanu stavku jednog korisnika i "podmetne" je pod drugog korisnika ili drugu stavku a da dešifrovanje ne pukne.

### 2.6 CSPRNG — kriptografski bezbedan generator slučajnih brojeva

Obični generatori slučajnih brojeva (kao `Math.random()` u JavaScript-u) **nisu bezbedni za kriptografiju** — njihov unutrašnji algoritam je predvidljiv, pa napadač koji zna dovoljno izlaza može da predvidi sledeće. **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator) koristi izvore prave nepredvidljivosti (šum iz operativnog sistema) i dizajniran je tako da se izlaz ne može predvideti. Projekat ih koristi svuda gde treba nasumičnost koja ima bezbednosnu težinu: salt, IV, ključevi, OTP kod, refresh token.

- U pregledaču: `crypto.getRandomValues`.
- Na serveru (Node.js): `crypto.randomInt`, `crypto.randomUUID`.

### 2.7 Poređenje u konstantnom vremenu (timing attack)

Kad se poredi dva niza bajtova (npr. da li je poslati kod tačan), naivno poređenje (`a === b` ili petlja koja stane čim nađe razliku) je **brže** kad se razlika nađe ranije. Napadač koji hiljadama puta šalje pokušaje i **meri koliko je server bio brz** može, teoretski, da izvuče informaciju bajt po bajt — ovo se zove **timing attack**. Rešenje je poređenje koje uvek troši isto vreme, bez obzira gde je razlika (uporedi se svaki bajt, bez ranog izlaska). Projekat ovo eksplicitno implementira (poglavlje 6.1).

### 2.8 Zero-knowledge arhitektura

Ovo je centralna ideja celog projekta. **Zero-knowledge** (u kontekstu menadžera lozinki, ne u smislu "zero-knowledge proofs" iz kriptografije) znači: **server nikad ne dobija podatak iz kog bi mogao da rekonstruiše tvoje lozinke**, čak ni da hoće, čak i da je kompromitovan.

To se postiže tako što se **sve šifrovanje i dešifrovanje dešava u tvom pregledaču**, ključevi se izvode iz tvoje master lozinke koju server nikad ne vidi, a serveru se šalje samo već-šifrovan sadržaj. Server je u suštini "glupi", ali pouzdani seif za nečitljive kutije — čuva ih, vraća ih kad zatražiš, ali ih ne može otvoriti.

---

## 3. Osnove veb bezbednosti

### 3.1 HTTP, HTTPS i TLS

**HTTP** je protokol kojim pregledač i server razmenjuju poruke (zahtev/odgovor). Sam po sebi, HTTP saobraćaj putuje **nešifrovan** — bilo ko na putu (npr. na istoj WiFi mreži) može da ga pročita ili izmeni.

**HTTPS** = HTTP preko **TLS**-a (Transport Layer Security), sloja koji šifruje ceo saobraćaj između pregledača i servera i proverava da server zaista jeste taj za koga se predstavlja (preko sertifikata). Bez HTTPS-a, čak i da su tvoji podaci dobro šifrovani na aplikacionom nivou (kao u SleepSafe-u), stvari poput lozinke za prijavu na email (van ovog sistema) ili same komunikacije bi mogle biti prisluškivane. Napomena o statusu HTTPS-a u ovom projektu je u poglavlju 13.

**Bitna posledica za ovaj projekat:** moderni pregledači dozvoljavaju upotrebu WebCrypto API-ja (2.5, 2.6 iznad) **samo** u "bezbednom kontekstu" — što znači HTTPS, ili `localhost`. Zato SleepSafe radi na `localhost` u razvoju, ali pristup sa **drugog** uređaja preko obične `http://192.168.x.x` adrese ne bi radio — kriptografske funkcije pregledača bi bile nedostupne.

### 3.2 Kolačići (cookies) i sesije

**Kolačić** je mali komad podataka koji server kaže pregledaču da zapamti, i pregledač ga automatski šalje nazad serveru pri svakom sledećem zahtevu ka istom sajtu. Koriste se da server "prepozna" da si to i dalje ti, bez da se svaki put ponovo prijavljuješ.

Bitna podešavanja kolačića za bezbednost:

- **HttpOnly** — JavaScript kod na stranici **ne može** da pročita ovaj kolačić. Štiti ga od krađe preko XSS napada (3.3).
- **Secure** — kolačić se šalje samo preko HTTPS-a, nikad preko običnog HTTP-a.
- **SameSite** — kontroliše da li se kolačić šalje kad zahtev dolazi sa **drugog** sajta. `Strict` znači "nikad", što je jaka odbrana od CSRF napada (3.4).

### 3.3 XSS (Cross-Site Scripting)

**XSS** je napad gde napadač uspe da ubaci **svoj JavaScript kod** u stranicu koju ti gledaš (npr. kroz polje za unos koje se kasnije prikaže bez "čišćenja"). Kad se to desi, taj kod se izvršava sa **tvojim** pravima, u tvom pregledaču — može da čita sve što ti vidiš, šalje zahteve u tvoje ime, krade podatke iz JavaScript memorije.

Osnovna odbrana: nikad ne ubacivati sirov, neproveren tekst direktno u HTML (izbegavati `innerHTML` sa korisničkim unosom). React biblioteka (4. poglavlje) ovo radi automatski — tekst koji prikažeš kroz React se po difoltu "eskejpuje" (posebni znakovi kao `<` se pretvaraju u bezopasan tekst), pa se sam kod ne izvršava.

### 3.4 CSRF (Cross-Site Request Forgery)

**CSRF** je napad gde te napadač namami na svoj (zlonamerni) sajt, koji u pozadini pošalje zahtev **ka sajtu na kome si već prijavljen** (npr. SleepSafe), koristeći tvoj pregledač. Pošto pregledač automatski šalje kolačiće za taj sajt, zahtev izgleda kao da dolazi od tebe — server ne može lako da razlikuje "stvarno sam ja kliknuo" od "zlonamerni sajt je poslao zahtev u moje ime".

Odbrane: `SameSite=Strict` kolačić (pregledač ga uopšte ne šalje kad zahtev dolazi sa drugog sajta) i provera `Origin` HTTP zaglavlja na serveru (server odbija zahtev koji ne dolazi sa poznatog sajta).

### 3.5 SQL injekcija

Ako se korisnički unos direktno "zalepi" u SQL upit kao tekst (npr. `"SELECT * FROM users WHERE email = '" + unos + "'"`), napadač može da upiše tekst koji **menja značenje upita** (npr. da doda `OR 1=1` i izvuče sve redove, ili obriše tabelu). Ovo se zove **SQL injekcija**.

Odbrana: **parametrizovani upiti** — korisnički unos se šalje bazi odvojeno od strukture upita, kao vrednost, nikad kao deo teksta upita. Alati koji automatski rade parametrizaciju (kao Prisma ORM, 4. poglavlje) praktično eliminišu ovaj rizik kad se koriste kako treba.

### 3.6 Enumeracija naloga

Ovo je suptilnija pretnja: čak i bez pristupa nalogu, napadač može da zloupotrebi **razlike u odgovorima** servera da sazna **koji email-ovi postoje** u sistemu (npr. "Pogrešna lozinka" znači da nalog postoji, a "Nalog ne postoji" znači da ne postoji — napadač probne razne email-ove i pravi listu registrovanih korisnika, što je opasno samo po sebi za privatnost, a i olakšava dalje napade). Odbrana je da server **uvek** vrati isti odgovor, bez obzira da li nalog postoji.

### 3.7 Brute force, credential stuffing i rate limiting

**Brute force** = pokušavanje ogromnog broja kombinacija (lozinki, kodova) dok se ne pogodi. **Credential stuffing** je varijanta gde napadač koristi lozinke procurele sa **drugih** sajtova (ljudi često koriste istu lozinku svuda) i proba ih na ovom sistemu.

**Rate limiting** (ograničenje broja zahteva) i **account lockout** (privremeno blokiranje naloga posle više neuspešnih pokušaja) su osnovne odbrane — usporavaju napadača do te mere da mu napad postaje nepraktičan.

### 3.8 Bezbednosna HTTP zaglavlja

Pored samih podataka, server može da pošalje dodatna **zaglavlja** (headers) koja govore pregledaču kako da se ponaša prema toj stranici:

- **CSP (Content-Security-Policy)** — govori pregledaču sa kojih izvora sme da učita skripte, stilove itd. Dobra CSP politika je jaka dodatna odbrana protiv XSS-a (čak i ako se zlonameran kod nekako ubaci, CSP može da spreči da se izvrši).
- **Cache-Control: no-store** — govori pregledaču (i posrednicima na mreži) da ne čuva kopiju odgovora, važno za osetljive podatke.
- Ostala zaglavlja koja sprečavaju "clickjacking" (ugrađivanje sajta u nevidljiv frame na tuđem sajtu radi prevare) i slično.

---

## 4. Tehnologije korišćene u projektu

### 4.1 TypeScript

**JavaScript** je programski jezik veba — jedini jezik koji nativno razume pregledač. **TypeScript** je "nadgradnja" JavaScript-a koja dodaje **statičke tipove** — pre nego što se kod pokrene, alat proverava da li se, na primer, funkciji koja očekuje broj slučajno ne prosleđuje tekst. Ovo hvata čitavu klasu grešaka **pre** izvršavanja, što je posebno vredno u bezbednosno osetljivom kodu (kripto operacije, validacija). Projekat koristi TypeScript svuda — i na klijentu i na serveru.

### 4.2 Node.js

**Node.js** je okruženje koje omogućava da se JavaScript/TypeScript kod izvršava **van** pregledača — na primer, na serveru. Zahvaljujući ovome, ceo projekat (klijent i server) koristi jedan jezik.

### 4.3 React

**React** je biblioteka za pravljenje korisničkih interfejsa. Umesto ručnog manipulisanja HTML-om, piše se u **komponentama** — funkcijama koje na osnovu trenutnog "stanja" (state) vraćaju opis kako interfejs treba da izgleda, a React se stara da stvarni ekran ažurira efikasno kad se stanje promeni. Kao što je pomenuto u 3.3, React automatski štiti od XSS-a jer po difoltu eskejpuje tekst koji prikazuje.

### 4.4 Vite

**Vite** je alat koji, tokom razvoja, servira klijentski kod pregledaču (uz trenutno osvežavanje pri izmeni fajla), a za produkciju ga "spakuje" (build) u optimizovane fajlove.

### 4.5 Fastify

**Fastify** je okvir (framework) za pisanje veb servera u Node.js-u — prima HTTP zahteve, rutira ih ka odgovarajućem kodu, šalje odgovore. Poznat je po brzini i po sistemu "plugin"-ova (helmet, cors, cookie, rate-limit — svi korišćeni u ovom projektu, poglavlje 8).

### 4.6 Zod

**Zod** je biblioteka za **validaciju šema** — piše se opis "kako tačno treba da izgleda ovaj podatak" (npr. "email mora biti tekst, validnog oblika, najviše 254 znaka"), a Zod na osnovu tog opisa proverava stvarne podatke i odbija sve što ne odgovara. Projekat drži Zod šeme u `packages/shared` da bi **i klijent i server** koristili **potpuno isti** opis pravila — pa nema situacije da klijent misli da je nešto dozvoljeno, a server ga odbije (ili obrnuto, još opasnije, da server nešto propusti što ne bi trebalo).

### 4.7 PostgreSQL i relacione baze podataka

**Relaciona baza podataka** čuva podatke u **tabelama** (redovi i kolone), sa mogućnošću da se tabele međusobno povežu (npr. jedan korisnik ima više sesija). **PostgreSQL** je konkretan, besplatan i vrlo raširen sistem za takve baze. Sa njim se komunicira jezikom **SQL** (Structured Query Language).

### 4.8 Prisma (ORM)

**ORM (Object-Relational Mapper)** je alat koji prevodi između SQL sveta (tabele, redovi) i sveta programskog jezika (objekti, klase), tako da programer piše `prisma.user.create(...)` umesto ručnog SQL teksta. **Prisma** dodatno generiše TypeScript tipove direktno iz šeme baze, pa greške u imenu kolone ili tipu hvata kompajler, ne tek kad se kod pokrene. Takođe upravlja **migracijama** — evidentiranim, ponovljivim koracima kojima se šema baze menja tokom vremena (poglavlje 8.2).

### 4.9 Docker i Docker Compose

**Docker** pakuje program zajedno sa svim što mu treba da radi (sistemske biblioteke, podešavanja) u **kontejner** — izolovano okruženje koje radi isto na bilo kom računaru, bez "kod mene radi, a kod tebe ne" problema. **Docker Compose** opisuje **više** kontejnera koji rade zajedno (u ovom projektu: baza i lažni email server, poglavlje 10.1) i pokreće ih jednom komandom.

### 4.10 pnpm i monorepo

**pnpm** je menadžer paketa za JavaScript/Node (kao npm, samo efikasniji sa diskom). **Monorepo** znači da više povezanih projekata (ovde: server, klijent, dva deljena paketa) žive u **jednom** git repozitorijumu, umesto u četiri odvojena. Ovo olakšava deljenje koda (kao Zod šeme) između klijenta i servera — jednostavno se uveze paket, bez kopiranja fajlova ili objavljivanja na javni registar.

### 4.11 SMTP, Nodemailer i Mailpit

**SMTP** je standardni protokol za slanje email-ova. **Nodemailer** je biblioteka koja iz Node.js koda šalje email preko SMTP-a. **Mailpit** je alat koji se koristi **samo u razvoju** — pretvara se da je pravi email server, ali sve poruke samo prikazuje u svom veb interfejsu (`localhost:8025`) umesto da ih stvarno šalje — korisno za testiranje bez slanja pravih email-ova.

### 4.12 WebCrypto API i Web Worker

**WebCrypto** (`crypto.subtle`, `crypto.getRandomValues`) je ugrađen API modernih pregledača za kriptografske operacije (enkripcija, heš, generisanje nasumičnih brojeva) — brz je jer koristi optimizovane implementacije pregledača, a ključevi kojima rukuje mogu biti označeni kao "neizvozivi" (ne mogu se pročitati kao sirovi bajtovi iz JavaScript koda, samo koristiti za enkripciju/dekripciju).

**Web Worker** je way da se deo JavaScript koda izvršava u **posebnoj niti**, paralelno sa glavnom stranicom. Argon2id (2.4) je namerno spor, pa bi bez Worker-a "zamrzao" ceo interfejs dok traje — projekat ga zato izvršava u Worker-u (poglavlje 9.5).

### 4.13 hash-wasm i WebAssembly

**WebAssembly (WASM)** je format koji omogućava da se kod pisan u drugim jezicima (ovde: C/Rust implementacija Argon2id-a) izvršava u pregledaču skoro brzinom nativnog koda. **hash-wasm** je biblioteka koja Argon2id isporučuje kao WASM modul, jer WebCrypto API (4.12) **ne podržava** Argon2id nativno.

### 4.14 jose (JWT biblioteka)

**JWT (JSON Web Token)** je kompaktan, potpisan token koji nosi neke podatke (ovde: id korisnika i id sesije) i **potpis** koji dokazuje da ga je izdao server i da nije menjan. Ko god ima tajni ključ kojim je token potpisan, može da ga proveri (i to brzo, bez pitanja baze). Server koristi **jose** biblioteku da izdaje i proverava ove tokene (poglavlje 8.4).

### 4.15 ESLint, Prettier i CI

**ESLint** analizira kod i upozorava na sumnjive obrasce (npr. neiskorišćena promenljiva, poređenje koje verovatno nije nameravano). **Prettier** automatski formatira kod (razmaci, navodnici) da ceo tim (ili, ovde, i čovek i asistent koji pišu kod) koristi isti stil. **CI (Continuous Integration)** — u ovom projektu GitHub Actions — automatski, pri svakoj izmeni, pokreće ove i druge provere (poglavlje 10.3), da se greška primeti odmah, ne tek kad neko drugi pokrene kod.

---

## 5. Arhitektura — kako su delovi povezani

```
┌─────────────────────────────┐         ┌─────────────────────────┐
│   PREGLEDAČ (apps/web)      │  HTTPS  │   SERVER (apps/api)      │
│                              │ ------> │                          │
│  React aplikacija            │         │  Fastify                │
│  Argon2id u Web Worker-u    │ <------ │  Validacija (Zod)        │
│  Sve šifruje/dešifruje ovde │         │  Autentikacija, sesije   │
│  Vault Key nikad ne izlazi  │         │  NE VIDI otvoren tekst   │
└──────────────┬───────────────┘         └────────────┬─────────────┘
               │                                        │
               │ koristi                                │ koristi
               ▼                                        ▼
   packages/crypto (WebCrypto)              PostgreSQL baza (šifrovani podaci)
   packages/shared (Zod šeme — koriste i klijent i server)
                                                          │
                                                          │ šalje email preko SMTP
                                                          ▼
                                                    Mailpit (razvoj) / pravi SMTP
```

**Ključna stvar:** klijent i server **dele** samo Zod šeme (`packages/shared`) — pravila oblika podataka. **Nikad** ne dele ključeve niti otvoren tekst. `packages/crypto` **postoji i koristi se na obe strane**, ali server ga koristi samo za sitne pomoćne funkcije (base64, poređenje u konstantnom vremenu, generisanje nasumičnih bajtova) — **nikad** za dešifrovanje stavki, jer server nema ključ kojim bi to uradio.

Klijent i server dele i **isti origin** (isti "sajt" iz ugla pregledača) — Vite razvojni server prosleđuje `/auth`, `/vault` i `/health` putanje ka API-ju ([vite.config.ts](apps/web/vite.config.ts)), pa se ponašaju kao jedan sajt, što pojednostavljuje kolačiće (SameSite, 3.2) i CORS (3.4 srodno).

Monorepo (4.10) struktura na disku:

```
apps/api        → server (Fastify + Prisma + PostgreSQL)
apps/web        → klijent (React + Vite)
packages/crypto → kriptografske funkcije, koristi ih i klijent i server
packages/shared → Zod šeme (oblik zahteva/odgovora), koristi ih i klijent i server
infra/          → Docker Compose (baza + Mailpit)
```

---

## 6. `packages/crypto` — kriptografsko jezgro

Ovo je najosetljiviji deo projekta — sve kriptografske operacije su namerno skupljene na jedno mesto, umesto rasute po celoj aplikaciji, da bi bile lakše za pregled i proveru.

### 6.1 `bytes.ts` — osnovni gradivni blokovi

- `randomBytes(length)` — CSPRNG (2.6), preko `crypto.getRandomValues`. Koristi se za sve gde treba nepredvidljivost sa bezbednosnom težinom (salt, IV, ključevi).
- `utf8Encode` / `utf8Decode` — pretvaranje teksta u bajtove i nazad (kripto funkcije rade sa bajtovima, ne sa tekstom direktno).
- `toBase64Url` / `fromBase64Url` — **Base64url** je način da se sirovi bajtovi (koji mogu sadržati bilo koju vrednost) predstave kao tekst siguran za URL-ove i JSON (samo slova, brojevi, `-` i `_`, bez `+`, `/`, `=` koji imaju posebno značenje u URL-ovima). Ovo **nije enkripcija** — samo promena zapisa, bilo ko može da dekoduje nazad. Koristi se jer JSON ne ume da nosi sirove bajtove.
- `constantTimeEqual` — poređenje u konstantnom vremenu (2.7), sprečava timing napade.

### 6.2 `kdf.ts` — izvođenje ključeva

Ovo je implementacija koncepata iz 2.4:

- `DEFAULT_KDF_PARAMS` — podrazumevani Argon2id parametri: 65536 KiB (64 MiB) memorije, 3 iteracije, paralelizam 1.
- `assertAcceptableKdfParams` — proverava da su parametri u **prihvatljivom opsegu** (memorija 19456 KiB do 1 GiB, iteracije 2 do 20, paralelizam do 16). Ovo je odbrana od **downgrade napada**: čak i da neko (npr. kompromitovan server) pokuša da klijentu podmetne preslabe parametre (npr. "koristi samo 1 iteraciju"), klijent to odbija.
- `deriveMasterKey` — poziva Argon2id (`hash-wasm`) nad lozinkom (normalizovanom Unicode NFKC formom, da se izbegnu suptilne razlike u zapisu istog teksta) i salt-om, daje **Master Key**.
- `hkdfSha256` — **HKDF** (HMAC-based Key Derivation Function) uzima jedan ključ i "razvlači" ga u jedan ili više novih ključeva, svaki vezan za drugu **oznaku (info)**, tako da poznavanje jednog izvedenog ključa ne otkriva ništa o drugom.
- `deriveKeys` — spaja prethodno: Master Key → HKDF sa oznakom `"sleepsafe/v1/auth-key"` daje **Auth ključ** (šalje se serveru), HKDF sa oznakom `"sleepsafe/v1/kek"` daje **KEK** (Key Encryption Key, ostaje samo na klijentu). Master Key i sirovi bajtovi KEK-a se odmah posle **eksplicitno brišu iz memorije** (`fill(0)`) — što pre nestanu iz RAM-a, to manje vremena postoje da bi mogli da procure (npr. kroz grešku u drugom delu koda, ili forenziku memorije).

**Zašto dva odvojena ključa iz iste lozinke?** Ovo je suštinski deo dizajna. Auth ključ ide serveru (da dokaže ko si), a KEK ostaje na klijentu (da otključa tvoje podatke). Da je to **isti** ključ, server bi, dobijajući ga radi provere prijave, **dobio i ključ kojim se sve dešifruje** — što bi potpuno srušilo "zero-knowledge" svojstvo (2.8). Razdvajanjem, server dokazuje da znaš lozinku a da nikad ne vidi ništa čime bi mogao da dešifruje tvoje podatke.

### 6.3 `aes.ts` — simetrična enkripcija

- `aesGcmEncrypt` / `aesGcmDecrypt` — implementacija AES-256-GCM (2.5) preko WebCrypto-a. IV od 12 bajtova (96 bita, standardna dužina za GCM) generiše se nasumično za **svaki** poziv `aesGcmEncrypt`. Tag je 16 bajtova (128 bita).
- Ako se dešifrovanje ne poklopi sa tagom (podatak je izmenjen, ili je ključ pogrešan), funkcija baca grešku — **nikad** ne vraća "verovatno pogrešan" tekst.

### 6.4 `vault.ts` — omotavanje ključeva i stavki

Ovo implementira hijerarhiju ključeva i format iz 2.8, konkretno:

- `wrapVaultKey` / `unwrapVaultKey` — "omotavanje" (wrap) je enkripcija **ključa** drugim ključem (umesto enkripcije običnog teksta). Vault Key (nasumičan AES-256 ključ) se omotava KEK-om pre slanja serveru, uz AAD konstantu `"sleepsafe/v1/vault-key"` (2.5 — AAD vezuje omotnicu za svrhu, sprečava zamenu sa nekim drugim šifrovanim podatkom).
- `createVault` — generiše potpuno nov, nasumičan Vault Key (preko WebCrypto `generateKey`, **neizvoziv** — JavaScript kod ga ne može pročitati kao sirove bajtove, samo koristiti za šifrovanje/dešifrovanje) i odmah ga omota KEK-om.
- `rewrapVaultKey` — koristi se pri promeni lozinke: Vault Key se otključa **starim** KEK-om (privremeno izvoziv, samo za ovu operaciju) i ponovo zaključa **novim** KEK-om. Sam Vault Key se **ne menja** — samo "kutija" oko njega.
- `encryptItem` / `decryptItem` — šifrovanje/dešifrovanje jedne stavke trezora. AAD je JSON niz `["sleepsafe/v1/item", userId, itemId]` — vezuje šifrat za **tačno tog** korisnika i **tačno tu** stavku, pa čak ni server (koji vidi id korisnika i id stavke, ali ne i sadržaj) ne bi mogao da "premesti" tuđu šifrovanu stavku pod drugi id a da se dešifrovanje ne pokvari.
- **Format omotnice**: `{v: 1, iv: "...", ct: "..."}` — `v` je broj verzije formata (omogućava buduće promene bez lomljenja starih podataka), `iv` i `ct` (šifrat + tag zajedno) su u base64url zapisu (6.1).

### 6.5 `errors.ts` i `index.ts`

`errors.ts` definiše `CryptoError`, sa kodovima poput `INVALID_INPUT`, `DECRYPT_FAILED`, `UNSUPPORTED_VERSION` — omogućava pozivaocu da razlikuje "pogrešna lozinka" od "pokvaren podatak" bez curenja detalja niže kriptografske greške.

`index.ts` je **jedina** tačka kroz koju se ovaj paket koristi spolja — izvozi samo ono što je stvarno potrebno (`deriveKeys`, `createVault`, `encryptItem`, `decryptItem`, itd.), a **ne** izvozi niskonivoske funkcije (`aesGcmEncrypt`, `argon2idRaw`, `hkdfSha256`) direktno. Ovo je namerna izolacija — što je manja "javna površina" kriptografskog koda, to je manje šansi da neko slučajno pogrešno upotrebi niskonivosku funkciju.

---

## 7. `packages/shared` — zajednička pravila

Sve ovde su **Zod šeme** (4.6) — definišu tačan oblik podataka koji putuju između klijenta i servera, i koristi ih **oboje**, kao što je objašnjeno u 5. poglavlju.

- `auth.ts` — šeme za email, Auth ključ (uvek tačno 43 base64url znaka = 32 bajta), KDF salt i parametre, omotnicu ključa (`wrappedKeyEnvelopeSchema`), registraciju, prijavu, JWT format.
- `account.ts` — šeme za promenu lozinke, brisanje naloga, informacije o sesiji.
- `item.ts` — `itemDataSchema`: oblik **otvorenog teksta** jedne stavke (naslov, korisničko ime, lozinka, URL, beleške) sa granicama dužine za svako polje. **Ovu šemu server nikad ne koristi** — server nikad ne vidi otvoren tekst stavke, samo njen šifrat. Koristi je samo klijent, da proveri sopstveni unos pre šifrovanja.
- `vault.ts` — `itemEnvelopeSchema` (oblik šifrovane omotnice, sa regularnim izrazima koji proveravaju tačnu dužinu IV-a i minimalnu dužinu šifrata), šeme za sinhronizaciju (`listItemsQuerySchema`, `syncItemSchema`).

Sve šeme koriste `z.strictObject`, što znači da **odbijaju** bilo koje polje koje nije eksplicitno očekivano — ako neko pošalje dodatno, neočekivano polje, ceo zahtev se odbija, umesto da se nepoznato polje tiho ignoriše.

---

## 8. `apps/api` — server

### 8.1 Redosled sklapanja: `server.ts` → `app.ts`

`server.ts` je ulazna tačka: učitava `.env` promenljive, validira konfiguraciju (8.2), pravi konekciju ka bazi i mailer, poziva `buildApp` i pokreće server da sluša na portu.

`app.ts` (`buildApp`) sklapa Fastify aplikaciju:

1. Registruje **helmet** plugin — dodaje bezbednosna HTTP zaglavlja (3.8), sa strogom CSP politikom (`default-src 'none'` — po difoltu ništa nije dozvoljeno).
2. Registruje **cors** plugin — dozvoljava zahteve **samo** sa `APP_URL` adrese (3.4), sa `credentials: true` (dozvoljava slanje kolačića).
3. Registruje **cookie** plugin — omogućava čitanje/pisanje kolačića (3.2).
4. Registruje **rate-limit** plugin — globalno ograničenje zahteva u minuti (3.7).
5. Dodaje `Cache-Control: no-store` na svaki odgovor (3.8).
6. Postavlja jedinstven format grešaka (`{error: {code, message}}`) — greške validacije (Zod) postaju 400, poznate greške aplikacije (`AppError`) zadržavaju svoj kod, sve ostalo (neočekivane greške) postaje generičan 500 bez detalja — ovo je odbrana od curenja internih informacija napadaču.
7. Registruje sve grupe ruta (8.6).

### 8.2 `config.ts` — konfiguracija i njena validacija

Sve promenljive okruženja (iz `.env`) prolaze kroz Zod šemu **pri pokretanju servera** — ako nešto fali ili je pogrešnog oblika, server se **uopšte ne pokreće**, umesto da radi sa nedefinisanim ponašanjem. Dodatne provere: `JWT_SECRET` i `SERVER_PEPPER` moraju biti različiti (da kompromitacija jednog ne ugrozi drugi) i dovoljno dugi (najmanje 32 znaka), a u produkciji ne smeju sadržati placeholder tekst iz primera.

### 8.3 `db.ts` i Prisma šema

`db.ts` pravi Prisma klijenta, povezanog preko `@prisma/adapter-pg` (adapter za PostgreSQL).

Šema (`schema.prisma`) ima pet tabela:

| Tabela | Svrha | Bitne kolone |
|---|---|---|
| `users` | Nalog korisnika | `authHash` (HMAC Auth ključa, ne sam ključ), `kdfSalt` + tri KDF parametra, `wrappedVaultKey` (JSON omotnica), `vaultRevision` (brojač za sinhronizaciju) |
| `sessions` | Aktivne prijave | `refreshTokenHash`, `previousRefreshTokenHash` (detekcija ponovne upotrebe, 8.5), `userAgent`, `expiresAt`, `revokedAt` |
| `otp_challenges` | Email kodovi za 2FA | `codeHash`, `purpose` (prijava ili potvrda email-a), `attempts`, `expiresAt`, `consumedAt` |
| `vault_items` | Šifrovane stavke | `envelope` (JSON, `null` znači obrisano — tombstone), `revision` (za sinhronizaciju) |
| `audit_events` | Bezbednosni log (8.8) | `type`, `userId` (opciono, preživljava brisanje naloga), `ip`, `userAgent` |

Svuda gde tabela pripada korisniku, postoji `onDelete: Cascade` (kad se korisnik obriše, brišu se i njegove sesije/kodovi/stavke) — **osim** `audit_events`, koja ima `onDelete: SetNull` (zapis o brisanju naloga treba da **preživi** samo brisanje, inače bi se izgubio baš najvažniji trag).

### 8.4 `security.ts` — kriptografske pomoćne funkcije na serveru

- `hashAuthKey` / `verifyAuthKey` — HMAC-SHA256 (2.2) Auth ključa sa `SERVER_PEPPER`, poređenje u konstantnom vremenu (2.7).
- `generateOtp` — CSPRNG (2.6) šestocifreni kod.
- `hashOtp` / `verifyOtp` — isti princip kao Auth ključ, samo za OTP kod.
- `generateRefreshToken` / `hashRefreshToken` — isto, za refresh token (8.5).
- `signAccessToken` / `verifyAccessToken` — izdavanje i provera JWT-a (4.14) preko `jose` biblioteke. Token nosi id korisnika (`sub`) i id sesije (`sid`), potpisan HS256 algoritmom (HMAC sa `JWT_SECRET`).
- `fakeKdfSalt` — deterministički (uvek isti za isti email), ali izgleda nasumično, "lažni" salt za email-ove koji ne postoje (8.7 — odbrana od enumeracije naloga, 3.6).

### 8.5 `sessions.ts` — upravljanje sesijama i rotacija refresh tokena

Sesija ima **dva** tokena, sa različitim ulogama:

- **Access token (JWT)** — kratkog veka (podrazumevano 15 min), nosi ga klijent u `Authorization` zaglavlju, **ne** čuva se u kolačiću.
- **Refresh token** — dugog veka (30 dana), čuva se u `HttpOnly` kolačiću (3.2), koristi se **samo** da se dobije nov access token kad stari istekne.

`rotateSession` pri svakoj upotrebi refresh tokena izdaje **nov** i **poništava stari**, ali pamti heš starog u `previousRefreshTokenHash`. Ako se **stari** (već iskorišćen) token ponovo pojavi, to je znak da je token **ukraden** i da ga koriste dve strane (pravi korisnik dobio je novi, napadač i dalje pokušava sa starim) — sistem to prepoznaje i **opoziva** celu sesiju. Kratak "grace" prozor od 10 sekundi postoji jer paralelni zahtevi sa iste stranice mogu legitimno da stignu skoro istovremeno.

### 8.6 Rute (`routes/`)

- **`auth.ts`** — registracija, prijava, email kod, refresh, odjava, profil (`/auth/me`). Detaljan tok u poglavlju 11.
- **`account.ts`** — promena lozinke, lista i opoziv sesija, brisanje naloga.
- **`vault.ts`** — CRUD (Create/Read/Update/Delete) nad šifrovanim stavkama i sinhronizacija (poglavlje 11.5). Bitno: `withVaultLock` zaključava red korisnika u bazi (`SELECT ... FOR UPDATE`) pre svake izmene, da dva istovremena zahteva ne bi "trkom" oštetila brojač revizije.
- **`health.ts`** — `/health`, proverava da li server može da priča sa bazom (korisno za monitoring, nije bezbednosna mera).

Svaka ruta koja radi sa korisnikovim podacima prvo zove `authenticate(request)` (8.7) i identitet **uvek** uzima iz njegovog povratka, nikad iz tela zahteva — direktna primena principa iz 1.2 i odbrana od "Elevation of Privilege" (1.4).

### 8.7 `authenticate.ts` — ko sme šta

`createAuthenticator` vraća funkciju koja: (1) čita `Bearer <token>` iz `Authorization` zaglavlja, (2) proverava JWT potpis i istek, (3) proverava da odgovarajuća sesija **i dalje postoji u bazi i nije opozvana**. Treći korak je bitan — sam JWT bi bio validan do isteka čak i da je sesija u međuvremenu opozvana (npr. korisnik je promenio lozinku); provera u bazi garantuje da opoziv **odmah** stupa na snagu.

### 8.8 `audit.ts` i `challenges.ts` — audit log i OTP kodovi

`challenges.ts` upravlja OTP kodovima (2FA, 1.3): izdavanje (`issueChallenge`), potvrda (`redeemChallenge` — atomski uvećava broj pokušaja **pre** provere koda, da paralelni pokušaji ne bi zaobišli limit), rok važenja i maksimalan broj pokušaja.

`audit.ts` (`recordAuditEvent`) upisuje red u `audit_events` tabelu pri prijavi (uspeloj i neuspeloj), odjavi, promeni lozinke i opozivu sesije — odbrana od **Repudiation** (1.4): ako neko kasnije tvrdi "nisam se ja prijavio/promenio lozinku", postoji zapisan trag sa vremenom, IP adresom i uređajem.

### 8.9 `emails.ts` i `mailer.ts`

`mailer.ts` definiše `Mailer` interfejs i `createSmtpMailer` (šalje preko SMTP-a, 4.11), sa proverom oblika email adrese pre slanja (odbrana od "header injection" — ubacivanja novih linija u zaglavlja email-a da bi se promenilo njegovo značenje).

`emails.ts` gradi tekst email-ova: OTP kod (2FA, sa upozorenjem da se kod nikad ne deli) i bezbednosna obaveštenja (promena lozinke, brisanje naloga) — ova druga služe da korisnik **primeti** ako neko drugi uradi nešto sa njegovim nalogom, čak i bez da gleda audit log.

### 8.10 `throttle.ts` — `FailureThrottle`

Broji neuspešne pokušaje **po email adresi** (ne po IP adresi, jer napadač lako menja IP, ali teže menja ciljanu email adresu) u vremenskom prozoru, i blokira dalje pokušaje kad se pređe prag (3.7). Ima gornju granicu broja zapamćenih email adresa, da sam mehanizam za odbranu ne bi postao vektor za trošenje memorije servera (odbrana odbrane, tzv. "defense in depth" primenjen na samu odbranu).

### 8.11 `errors.ts`

Definiše `AppError` — jedinstven način da bilo koji deo servera kaže "ovo je greška, sa ovim HTTP statusom i ovim kodom", koju `app.ts` (8.1) zna kako da pretvori u odgovor korisniku.

---

## 9. `apps/web` — klijent (ono što vidiš u pregledaču)

### 9.1 Ulazna tačka: `main.tsx`

Pravi sve glavne objekte (HTTP klijent, AuthStore) i "montira" React aplikaciju u stranicu. Ovde se odlučuje **koje** konkretne implementacije se koriste (npr. `createWorkerDeriver` — izvođenje ključeva u Web Worker-u, 4.12).

### 9.2 `App.tsx` — koji ekran se prikazuje

Jednostavna komponenta koja, na osnovu trenutnog **stanja** (booting/signedOut/verifyingEmail/loginCode/locked/unlocked, definisano u `auth/store.ts`), bira i prikazuje odgovarajući ekran.

### 9.3 `auth/store.ts` — `AuthStore`, mozak klijenta

Ovo je centralni objekat koji drži **celokupno stanje prijave** i sadrži svu logiku registracije, prijave, otključavanja, promene lozinke, brisanja naloga. Koristi šablon zvan "spoljni store" (`subscribe`/`getState`), koji React čita preko `useSyncExternalStore` hook-a (`auth/context.tsx`) — ovo znači da logika **nije** zavezana za React i lakše se prati kao običan TypeScript kod.

**Najbitnija invarijanta u celom klijentu:** čim se stanje pomeri **iz** `'unlocked'` u bilo koje drugo stanje (zaključavanje, odjava, istek sesije, brisanje naloga), `VaultStore` (9.6) se **odmah uništava** — ključ i sve dešifrovane stavke nestaju iz memorije. Ovo je implementirano na jednom mestu (u internoj `setState` metodi), pa nijedan put kroz kod ne može da je zaobiđe.

Bitne metode:
- `register` / `verifyEmail` — tok iz 11.1.
- `login` / `verifyLoginCode` — tok iz 11.2.
- `unlock` — kad se stranica ponovo otvori sa još važećom sesijom, traži se samo master lozinka (ne novi email kod) — otvara se Vault Key lokalno.
- `openWithPassword` (privatna) — proverava lozinku **lokalno**, pokušajem otključavanja Vault Key-a, **pre** nego što bilo šta ide serveru. Zato pogrešna lozinka pri promeni lozinke ili brisanju naloga ne troši serverske pokušaje (throttle, 8.10) niti otkriva ništa serveru.
- `changePassword` — tok iz 11.6.
- `deleteAccount` — tok iz 11.8.

### 9.4 `auth/context.tsx`, `auth/errors.ts`, `auth/policy.ts`, `auth/agent.ts`

- `context.tsx` — React "lepak" (Context + `useSyncExternalStore`) koji povezuje `AuthStore` sa komponentama.
- `errors.ts` — `ClientError`, tipizovani kodovi grešaka specifičnih za klijent (npr. `WRONG_PASSWORD`, `WEAK_KDF`).
- `policy.ts` — `MIN_MASTER_PASSWORD_LENGTH` (12 znakova) i `strongerKdfParams` (pri promeni lozinke, novi KDF parametri nikad nisu slabiji od trenutnih niti od preporučenih — samo mogu da rastu).
- `agent.ts` — `describeUserAgent`, pretvara sirovi `User-Agent` tekst u čitljiv opis ("Chrome na Windows") za ekran sesija.

### 9.5 `crypto/deriver.ts` i `crypto/kdf.worker.ts`

`kdf.worker.ts` je kod koji radi **u Web Worker-u** (4.12) — poziva `deriveKeys` iz `packages/crypto` i vraća rezultat glavnoj niti preko poruke. `deriver.ts` (`createWorkerDeriver`) pokreće nov worker za svaki poziv i gasi ga čim dobije odgovor — dok worker radi, interfejs stranice ostaje odziv (korisnik vidi "Izvodim ključeve…" umesto zamrznute stranice).

### 9.6 `vault/store.ts` — `VaultStore`

Drži dešifrovane stavke **samo u memoriji** (nikad u `localStorage` ili slično — kad se stranica zatvori ili zaključa, sve nestaje). Glavne odgovornosti:

- `create` / `update` / `remove` — šifruje stavku (`encryptItem` iz `packages/crypto`) i šalje je serveru sa `baseRevision` (za detekciju konflikta, 11.5).
- `sync` — povlači promene sa servera (11.5), koristeći `cursor` (poslednju viđenu reviziju).
- `apply` — za svaku stavku sa servera, pokušava dešifrovanje; ako ne uspe (oštećena, ili šifrovana drugim ključem), stavka se označava kao "nečitljiva" umesto da sruši ceo prikaz.
- `dispose` — briše ključ i sve stavke iz memorije (zove ga `AuthStore` čim se napusti `'unlocked'` stanje, 9.3).

### 9.7 `vault/hooks.ts`, `vault/clipboard.ts`, `vault/search.ts`, `vault/url.ts`, `vault/generator.ts`, `vault/exchange.ts`

- `hooks.ts` — `useIdleLock` (automatsko zaključavanje posle 5 min bez aktivnosti — miš, tastatura, dodir), `useVaultSync` (pokreće sinhronizaciju pri otvaranju, povratku fokusa i periodično).
- `clipboard.ts` — `ClipboardGuard`: briše kopiranu lozinku iz klipborda posle 30 sekundi. Ovo je odbrana od scenarija gde neko drugi (druga aplikacija, ili neko ko dobije fizički pristup uređaju) kasnije pročita klipbord.
- `search.ts` — pretraga bez razlike u velikim/malim slovima i dijakritici, **nikad** ne pretražuje polje lozinke.
- `url.ts` — `toSafeUrl`, dozvoljava samo `http`/`https` linkove (odbrana od `javascript:` sheme, koja bi izvršila kod ako bi se otvorila kao link — povezano sa XSS, 3.3).
- `generator.ts` — generator lozinki, koristi CSPRNG (2.6) preko `secureRandomInt` (ravnomerna raspodela, bez pristrasnosti prema manjim brojevima).
- `exchange.ts` — izvoz (JSON/CSV, **nešifrovan** fajl, sa jasnim upozorenjem korisniku) i uvoz (iz SleepSafe JSON-a ili CSV-a drugih menadžera lozinki), sa proverom veličine i broja stavki.

### 9.8 `api/http.ts`, `api/auth.ts`, `api/vault.ts`

`http.ts` (`HttpClient`) je jedina tačka koja stvarno zove `fetch`: drži access token **samo u JavaScript memoriji** (ne u kolačiću niti `localStorage`), automatski pokušava `refresh` kad dobije 401 (istekao token) i ponavlja zahtev, i proverava oblik svakog odgovora Zod šemom pre nego što ga vrati pozivaocu (dodatna provera pored onoga što server garantuje — klijent ne veruje serveru "na reč").

`auth.ts` i `vault.ts` su tanki slojevi iznad `HttpClient`-a, po jedna funkcija za svaku API rutu (8.6).

### 9.9 Ekrani (`screens/`)

- `SignedOutScreen.tsx` — prijava i registracija (sa obaveznom potvrdom "razumem da se lozinka ne može povratiti" — jer je zero-knowledge, 2.8, nema tehničkog načina da server vrati zaboravljenu lozinku).
- `CodeScreen.tsx` — unos šestocifrenog email koda (2FA, 1.3), zajednički za potvrdu email-a i prijavu.
- `UnlockScreen.tsx` — unos master lozinke kad je sesija još važeća.
- `VaultScreen.tsx` — lista stavki, pretraga, dugmad za zaključavanje/odjavu, ulaz u ekran naloga.
- `ItemForm.tsx` / `ItemView.tsx` — dodavanje/izmena i pregled jedne stavke (sa kopiranjem preko `ClipboardGuard`, sakrivenom lozinkom po difoltu, i potvrdom pre brisanja).
- `AccountScreen.tsx` — četiri kartice: sesije, promena lozinke, izvoz/uvoz, brisanje naloga.

### 9.10 `components/`, `hooks.ts`, `errors.ts`, `strings.ts`, `styles.css`

- `Fields.tsx` — ponovo upotrebljiva polja forme (tekst, lozinka sa dugmetom prikaži/sakrij, poruka greške).
- `GeneratorPanel.tsx` — interfejs za generator lozinki (9.7).
- `download.ts` — pokreće preuzimanje fajla u pregledaču (za izvoz).
- `hooks.ts` (koren) — `useAction`, generički hook za "izvrši async akciju, prati da li je u toku i eventualnu grešku".
- `errors.ts` (koren) — `describeError`, pretvara sve vrste grešaka (klijent, vault, API) u čitljivu poruku na srpskom.
- `strings.ts` — **svi** tekstovi interfejsa na jednom mestu (srpski jezik), lakše za održavanje i prevod.
- `styles.css` — CSS sa promenljivama (`--bg`, `--text`, itd.) koje se menjaju za svetlu/tamnu temu preko `prefers-color-scheme`.

---

## 10. Infrastruktura, alati i podešavanja

### 10.1 `infra/docker-compose.yml`

Pokreće **samo** dva kontejnera (4.9), aplikacija sama **nije** kontejnerizovana (pokreće se direktno preko Node.js-a/`pnpm`):

- `postgres` — baza (8.3), port vezan **samo** na `127.0.0.1` (nije dostupna spolja), sa `healthcheck` proverom.
- `mailpit` — lažni email server za razvoj (4.11).

### 10.2 `.env.example`, `.gitignore`

`.env.example` je predložak — kopira se u `.env` (koji se **nikad** ne commit-uje, vidi `.gitignore`) i popunjava stvarnim vrednostima. Sadrži lozinku baze, `JWT_SECRET`, `SERVER_PEPPER` i SMTP podešavanja.

`.gitignore` isključuje, pored uobičajenog (`node_modules`, build izlaz), i osetljive/generisane stvari: `.env*` (osim primera), sertifikate (`*.pem`, `*.key`), generisani Prisma klijent, lokalne podatke baze.

### 10.3 CI (`.github/workflows/ci.yml`)

Pri svakom push-u ili pull request-u na `main`, automatski se (4.15) redom proverava: instalacija sa **zaključanim** verzijama zavisnosti (`--frozen-lockfile` — sprečava da CI slučajno povuče noviju, neispitanu verziju paketa), formatiranje (Prettier), lint (ESLint), tipovi (TypeScript), i da li se klijent uspešno builduje. Projekat **nema** automatske testove (namerna odluka, vidi 13. poglavlje) — CI ne pokreće ni bazu ni Mailpit, jer mu ne trebaju za ove provere.

### 10.4 `package.json` fajlovi, `pnpm-workspace.yaml`, `tsconfig.base.json`, `eslint.config.js`, `.prettierrc`

- Koren `package.json` drži zajedničke skripte (`typecheck`, `lint`, `format`, `db:*`, `dev:*`) i deljene dev-alate.
- `pnpm-workspace.yaml` govori pnpm-u (4.10) da su `apps/*` i `packages/*` deo istog monorepoa.
- `tsconfig.base.json` — stroga TypeScript podešavanja koja svi paketi nasleđuju (`strict`, `noUncheckedIndexedAccess` — sprečava pristup nizu/objektu bez provere da element stvarno postoji).
- `eslint.config.js` — pravila lint-a, uključujući posebna pravila za React hook-ove u `apps/web`.
- `.prettierrc` — pravila formatiranja (navodnici, tačka-zarez, širina reda).

---

## 11. Tokovi kroz sistem, korak po korak

### 11.1 Registracija

1. Klijent generiše salt (6.1), izvodi Auth ključ i KEK (6.2), pravi nov Vault Key i omotnicu (6.4).
2. Šalje serveru: email, Auth ključ, KDF parametre, omotnicu — **nikad** lozinku niti KEK.
3. Server proverava da parametri nisu preslabi (8.2/6.2), pravi red u `users`, izdaje OTP kod (8.8) i šalje ga na email (8.9) — asinhrono, da brzina odgovora ne otkriva da li slanje uspeva.
4. Ako email već postoji i **potvrđen** je, server vraća **isti** izgled odgovora kao za uspešnu registraciju (lažni `challengeId`) — odbrana od enumeracije naloga (3.6).
5. Korisnik unosi kod (`CodeScreen`), `verify-email` postavlja `emailVerifiedAt`.

### 11.2 Prijava

1. `prelogin` vraća KDF parametre i salt za dati email — ili **lažne, ali dosledne** vrednosti ako email ne postoji/nije potvrđen (fakeKdfSalt, 8.4), da napadač ne može da razlikuje "ne postoji" od "postoji" po odgovoru.
2. Klijent izvodi ključeve, šalje Auth ključ.
3. Server poredi (HMAC + konstantno vreme, 8.4) — za nepostojeći nalog poredi sa **lažnim** heš-em, da vreme odgovora bude slično u oba slučaja.
4. Server izdaje OTP kod, klijent ga unosi (`verify-otp`), server izdaje JWT access token i refresh kolačić (8.5).
5. Klijent zove `/auth/me`, lokalno otključava Vault Key, ulazi u stanje `unlocked`.

### 11.3 Zaključavanje i ponovno otključavanje

Zaključavanje (ručno ili automatsko posle neaktivnosti, 9.7) briše ključ i stavke iz memorije, ali **ne** odjavljuje sa servera — sesija (kolačić) ostaje važeća. Ponovno otključavanje traži **samo** master lozinku (ne novi email kod), jer je drugi faktor (2FA) već zadovoljen za tu sesiju.

### 11.4 Dodavanje/izmena/brisanje stavke

Klijent šifruje stavku lokalno (`encryptItem`, 6.4) i šalje omotnicu serveru sa `baseRevision` — brojem revizije koju je klijent poslednji put video za tu stavku. Server, unutar zaključanog reda (8.6), proverava da li se `baseRevision` poklapa sa onim u bazi; ako ne (neko drugi je izmenio u međuvremenu), vraća 409 konflikt. Brisanje ne uklanja red iz baze nego postavlja "tombstone" (`envelope = null`, `deletedAt`), da bi se brisanje moglo ispravno preneti i na druge uređaje.

### 11.5 Sinhronizacija između uređaja

Server ima brojač `vaultRevision` po korisniku, koji raste sa **svakom** izmenom bilo koje stavke. Klijent pamti do koje revizije je stigao (`cursor`) i periodično/pri fokusu (9.7) traži samo stavke **novije** od toga (`GET /vault/items?since=cursor`). Svaka nova stavka se dešifruje lokalno. Ovo **nije** pravo spajanje (merge) dva izvora — server je jedini autoritativni izvor, a klijent samo puni svoj (privremeni, u memoriji) prikaz i prijavljuje na kojoj je verziji bio kad nešto menja, radi otkrivanja konflikta.

### 11.6 Promena master lozinke

Klijent lokalno proverava trenutnu lozinku (pokušajem otključavanja, 9.3 — `openWithPassword`), pa tek onda računa novu (sa KDF parametrima koji nikad ne opadaju, `policy.ts`), ponovo omotava (ne re-šifruje!) Vault Key novim KEK-om. Server, u jednoj transakciji: menja heš lozinke, salt, parametre i omotnicu, opoziva **sve ostale** sesije (bezbednosna mera — ako je neko ukrao pristup, promena lozinke ga izbacuje) i upisuje audit zapis (8.8). Korisnik dobija email obaveštenje.

### 11.7 Izvoz i uvoz

Oba se dešavaju **potpuno na klijentu** — ništa se ne šalje serveru mimo normalnog (već šifrovanog) upisa stavki. Izvoz traži lokalnu potvrdu lozinke i eksplicitnu potvrdu da korisnik razume da fajl **nije** šifrovan. Uvoz parsira JSON ili CSV (uz automatsko prepoznavanje formata drugih menadžera lozinki), pa upisuje stavke jednu po jednu (svaka se posebno šifruje).

### 11.8 Brisanje naloga

Klijent lokalno proverava lozinku, šalje Auth ključ. Server ga proverava, **kaskadno** briše sve povezano (sesije, OTP kodove, stavke — `onDelete: Cascade`, 8.3), šalje email obaveštenje. Audit zapis o samom brisanju je posebno dizajniran da **preživi** ovo brisanje (`onDelete: SetNull`, 8.3/8.8).

---

## 12. Šta se štiti i od koga (model pretnji)

Primena STRIDE-a (1.4) na SleepSafe:

| Kategorija | Konkretan primer napada | Odbrana u ovom projektu |
|---|---|---|
| **Spoofing** | Napadač se prijavljuje tuđim nalogom | Auth ključ (izveden iz lozinke koju samo korisnik zna) + email kod kao drugi faktor |
| **Tampering** | Server (ili neko na putu) menja šifrovanu stavku | AES-GCM tag + AAD vezan za korisnika i stavku (6.4) — svaka izmena razbija dešifrovanje |
| **Repudiation** | Korisnik (ili napadač u njegovo ime) tvrdi da nije radio neku radnju | Audit log (8.8) — prijava, odjava, promena lozinke, opoziv sesije, sa vremenom i IP adresom |
| **Information Disclosure** | Krađa cele baze podataka | Server nikad ne čuva otvoren tekst ni ključeve — samo omotnice i HMAC otiske (2.8, 8.3) |
| **Denial of Service** | Napadač zatrpa `/auth/login` zahtevima | Globalni i po-ruti rate limit (8.1), `FailureThrottle` (8.10) |
| **Elevation of Privilege** | Korisnik pokuša da pristupi tuđim stavkama | Identitet se uzima isključivo iz proverene sesije, nikad iz tela zahteva (8.6, 8.7) |

Dodatne, konkretnije pretnje i njihove odbrane:

- **Pogađanje lozinke (offline, da je baza procurila)** — Argon2id (2.4/6.2) čini svaki pokušaj skup.
- **Enumeracija naloga** (3.6) — isti odgovori bez obzira da li nalog postoji (11.1, 11.2).
- **XSS** (3.3) — React eskejpovanje, bez `innerHTML`, provera URL-a pre prikaza kao link (9.7).
- **CSRF** (3.4) — `SameSite=Strict` kolačić + provera `Origin` zaglavlja (8.6).
- **SQL injekcija** (3.5) — Prisma parametrizuje sve upite.
- **Krađa sesije** — access token samo u memoriji (9.8), refresh token `HttpOnly`, rotacija sa detekcijom ponovne upotrebe (8.5).
- **Downgrade KDF parametara** — klijent odbija preslabe parametre čak i da mu ih server pošalje (6.2).
- **Zaboravljen otključan uređaj** — automatsko zaključavanje posle neaktivnosti (9.7).
- **Klipbord** — automatsko brisanje posle 30 sekundi (9.7).
- **Zlonameran uvozni fajl** — granice veličine/broja stavki, validacija svakog reda (9.7).

---

## 13. Poznata ograničenja

Ovo je namerno iskren spisak — priznavanje granica je deo dobre bezbednosne prakse (bolje reći "ovo nismo rešili" nego ostaviti utisak da jeste rešeno kad nije):

- **HTTPS nije podešen u samom repozitorijumu.** WebCrypto (2.5, 3.1) zahteva HTTPS ili `localhost`, pa pristup sa drugog uređaja preko obične LAN adrese trenutno ne radi. Trajno rešenje (Tailscale, Cloudflare Tunnel, ili lokalni CA sertifikat) nije odlučeno.
- **Nema oporavka zaboravljene master lozinke.** Ovo je direktna posledica zero-knowledge dizajna (2.8) — da postoji način da se lozinka oporavi, server bi morao da drži nešto čime bi mogao i sam da dešifruje podatke.
- **SPA nema svoju CSP politiku** — samo API odgovori imaju CSP zaglavlje (8.1); statička HTML stranica klijenta trenutno nema.
- **Brojač neuspelih pokušaja prijave (`FailureThrottle`, 8.10) je u memoriji procesa** — restart servera ga resetuje.
- **Audit log (8.8) nema politiku brisanja starih zapisa**, niti korisnički vidljiv ekran (gleda se direktno u bazi, npr. preko Prisma Studio).
- **Nema automatskih testova** — namerna odluka (manje održavanja za projekat ovog obima); CI proverava samo formatiranje, lint, tipove i da li se klijent builduje.
- **Server isporučuje i sam klijentski kod** — u teoriji, kompromitovan server bi mogao da isporuči izmenjenu verziju klijenta koja bi, na primer, slala lozinku negde drugde. Ovo je poznato, prihvaćeno ograničenje svih veb-baziranih (ne desktop/ekstenzija) zero-knowledge alata.

---

## 14. Rečnik pojmova

| Pojam | Kratko objašnjenje |
|---|---|
| AAD | Dodatni podaci uključeni u proveru integriteta enkripcije, ali ne i šifrovani (2.5) |
| AEAD | Enkripcija koja pored poverljivosti daje i integritet (2.5) |
| AES-GCM | Simetrična enkripcija + integritet, korišćena za sve podatke u SleepSafe-u (2.5, 6.3) |
| Argon2id | KDF algoritam, pretvara lozinku u ključ namerno sporo (2.4, 6.2) |
| Auth ključ | Deo izveden iz lozinke koji se šalje serveru radi dokazivanja identiteta (6.2) |
| Base64url | Zapis sirovih bajtova kao teksta bezbednog za URL/JSON (6.1) |
| CSPRNG | Generator slučajnih brojeva bezbedan za kriptografiju (2.6) |
| CSRF | Napad koji zloupotrebljava tvoju već-prijavljenu sesiju sa tuđeg sajta (3.4) |
| CSP | HTTP zaglavlje koje ograničava odakle stranica sme da učita kod (3.8) |
| Grace prozor | Kratak dozvoljen razmak vremena, ovde: pri detekciji ponovne upotrebe refresh tokena (8.5) |
| HKDF | Funkcija koja jedan ključ "razvlači" u više odvojenih ključeva (6.2) |
| HMAC | Heš + tajni ključ, dokazuje i integritet i autentičnost (2.2) |
| IV (nonce) | Nasumičan broj korišćen jednom po enkripciji, nikad ponovljen za isti ključ (2.5) |
| JWT | Potpisan token koji nosi podatke i dokaz da nije menjan (4.14, 8.4) |
| KDF | Funkcija koja lozinku pretvara u kriptografski ključ, namerno sporo (2.4) |
| KEK | Ključ koji ostaje samo na klijentu i otključava Vault Key (6.2) |
| Omotavanje (wrap) | Enkripcija ključa drugim ključem, umesto enkripcije teksta (6.4) |
| OTP | Jednokratni kod, ovde poslat na email kao drugi faktor prijave (1.3, 8.8) |
| Pepper | Jedna tajna vrednost, ista za sve, čuva se odvojeno od baze (2.3) |
| Salt | Nasumična vrednost, različita po korisniku, javno se čuva uz heš (2.3) |
| STRIDE | Okvir za sistematsko nabrajanje pretnji (1.4, 12) |
| Tombstone | Zapis koji označava "ovo je obrisano" umesto stvarnog brisanja reda, radi sinhronizacije (8.3, 11.4) |
| Vault Key | Nasumičan ključ kojim se šifruju stvarne stavke trezora (6.4) |
| Zero-knowledge | Server nikad ne dobija podatak kojim bi mogao da dešifruje korisnikove tajne (2.8) |

---

*Ovaj dokument opisuje stanje koda u trenutku pisanja. Ako se kod menja, ovaj fajl treba ručno ažurirati — ne generiše se automatski.*
