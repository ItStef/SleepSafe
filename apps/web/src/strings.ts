export const t = {
  appName: 'SleepSafe',
  tagline: 'Menadžer lozinki. Sve se šifruje na vašem uređaju, server nikad ne vidi vaše podatke.',
  loading: 'Učitavanje…',

  tabs: { login: 'Prijava', register: 'Registracija' },

  fields: {
    email: 'Email adresa',
    password: 'Master lozinka',
    confirm: 'Ponovite master lozinku',
    code: 'Kod iz emaila',
    show: 'Prikaži',
    hide: 'Sakrij',
  },

  notices: {
    emailVerified: 'Email je potvrđen. Sada se možete prijaviti.',
    sessionExpired: 'Sesija je istekla ili je odjavljena. Prijavite se ponovo.',
    serverUnavailable: 'Server trenutno nije dostupan. Pokušajte ponovo za nekoliko trenutaka.',
    accountDeleted: 'Nalog i svi podaci su trajno obrisani.',
  },

  login: {
    submit: 'Prijavi se',
    working: 'Izvodim ključeve…',
  },

  register: {
    intro:
      'Master lozinka štiti sve vaše podatke. Ona se nikad ne šalje serveru, pa je zato nemoguće povratiti.',
    submit: 'Napravi nalog',
    working: 'Pripremam ključeve…',
    acknowledge:
      'Razumem da se master lozinka ne može povratiti. Ako je zaboravim, podaci su trajno izgubljeni.',
  },

  code: {
    verifyEmailTitle: 'Potvrdite email',
    verifyEmailIntro: (email: string) => `Poslali smo šestocifreni kod na ${email}.`,
    loginTitle: 'Unesite kod za prijavu',
    loginIntro: (email: string) => `Poslali smo šestocifreni kod na ${email}.`,
    submit: 'Potvrdi',
    resend: 'Pošalji kod ponovo',
    resent: 'Novi kod je poslat.',
    back: 'Nazad',
  },

  unlock: {
    title: 'Otključajte vault',
    intro: (email: string) => `Prijavljeni ste kao ${email}. Unesite master lozinku.`,
    submit: 'Otključaj',
    working: 'Otključavam…',
    logout: 'Odjavi se',
  },

  vault: {
    title: 'Vaš vault',
    signedInAs: (email: string) => `Prijavljeni ste kao ${email}`,
    lock: 'Zaključaj',
    logout: 'Odjavi se',
    add: 'Nova stavka',
    search: 'Pretraga',
    count: (shown: number, total: number) =>
      shown === total ? `Stavki: ${total}` : `Prikazano ${shown} od ${total}`,
    loading: 'Učitavam stavke…',
    empty: 'Vault je prazan. Dodajte prvu stavku.',
    noResults: 'Nema rezultata za ovu pretragu.',
    loadFailed: 'Stavke nisu učitane.',
    syncFailed: 'Osvežavanje nije uspelo. Prikazane su poslednje poznate stavke.',
    retry: 'Pokušaj ponovo',
    unreadable: (count: number) =>
      count === 1
        ? '1 stavka se ne može otvoriti (oštećena je ili je šifrovana drugim ključem).'
        : `${count} stavki se ne može otvoriti (oštećene su ili su šifrovane drugim ključem).`,
    untitledHint: 'Bez korisničkog imena',
  },

  item: {
    back: 'Nazad',
    edit: 'Izmeni',
    delete: 'Obriši',
    username: 'Korisničko ime',
    password: 'Lozinka',
    url: 'Adresa',
    notes: 'Beleške',
    updated: (when: string) => `Izmenjeno: ${when}`,
    hidden: 'Sakrivena',
    reveal: 'Prikaži',
    conceal: 'Sakrij',
    copy: 'Kopiraj',
    copyUsernameLabel: 'Kopiraj korisničko ime',
    copyPasswordLabel: 'Kopiraj lozinku',
    copiedUsername: 'Korisničko ime je kopirano.',
    copiedPassword: (seconds: number) =>
      `Lozinka je kopirana. Klipbord se briše za ${seconds} sekundi.`,
    copyFailed: 'Kopiranje nije uspelo. Pregledač nije dozvolio pristup klipbordu.',
    unsafeUrl: 'Adresa nije http(s), pa se ne otvara kao link.',
    confirmDelete: (title: string) => `Trajno obrisati „${title}“? Ovo se ne može poništiti.`,
    confirmYes: 'Da, obriši',
    confirmNo: 'Odustani',
    empty: 'nije uneto',
  },

  form: {
    newTitle: 'Nova stavka',
    editTitle: 'Izmena stavke',
    title: 'Naslov',
    save: 'Sačuvaj',
    saving: 'Čuvam…',
    cancel: 'Odustani',
    generator: 'Generator lozinki',
    hideGenerator: 'Sakrij generator',
  },

  generator: {
    length: 'Dužina',
    lower: 'Mala slova (a-z)',
    upper: 'Velika slova (A-Z)',
    digits: 'Cifre (0-9)',
    symbols: 'Simboli (!@#…)',
    avoidAmbiguous: 'Izbegni slične znakove (I, l, 1, O, 0, o)',
    regenerate: 'Nova lozinka',
    use: 'Koristi ovu lozinku',
    entropy: (bits: number) => `Približno ${bits} bita entropije`,
    invalid: (min: number, max: number) =>
      `Izaberite bar jednu grupu znakova i dužinu od ${min} do ${max}.`,
  },

  account: {
    open: 'Nalog',
    title: 'Nalog',
    back: 'Nazad',
    tabs: {
      sessions: 'Uređaji',
      password: 'Lozinka',
      transfer: 'Izvoz i uvoz',
      delete: 'Brisanje',
    },
    sessions: {
      title: 'Prijavljeni uređaji',
      hint: 'Ako ne prepoznajete neki uređaj, odjavite ga i promenite master lozinku.',
      loading: 'Učitavam…',
      current: 'Ovaj uređaj',
      created: (when: string) => `Prijavljen: ${when}`,
      lastUsed: (when: string) => `Poslednja aktivnost: ${when}`,
      revoke: 'Odjavi',
      revokeLabel: (name: string) => `Odjavi uređaj ${name}`,
      revokeOthers: 'Odjavi sve ostale',
      none: 'Nema drugih prijavljenih uređaja.',
    },
    password: {
      title: 'Promena master lozinke',
      intro:
        'Nova lozinka važi odmah. Svi ostali uređaji se odjavljuju, a vaši podaci ostaju netaknuti.',
      current: 'Trenutna master lozinka',
      next: 'Nova master lozinka',
      confirm: 'Ponovite novu master lozinku',
      submit: 'Promeni lozinku',
      working: 'Menjam…',
      done: 'Master lozinka je promenjena. Ostali uređaji su odjavljeni.',
    },
    delete: {
      title: 'Brisanje naloga',
      warning: 'Nalog i sve šifrovane stavke se trajno brišu sa servera. Ovo se ne može poništiti.',
      password: 'Master lozinka',
      acknowledge: 'Razumem da se nalog i svi podaci brišu trajno, bez mogućnosti povraćaja.',
      submit: 'Trajno obriši nalog',
      working: 'Brišem…',
    },
  },

  transfer: {
    exportTitle: 'Izvoz',
    exportWarning:
      'Izvezeni fajl NIJE šifrovan: svaka lozinka u njemu je vidljiva. Čuvajte ga kratko i obrišite ga čim završite.',
    exportAcknowledge: 'Razumem da izvezeni fajl nije šifrovan.',
    password: 'Master lozinka (potvrda)',
    exportJson: 'Izvezi JSON',
    exportCsv: 'Izvezi CSV',
    exportWorking: 'Izvozim…',
    exportEmpty: 'Vault je prazan: nema šta da se izveze.',
    exported: (count: number) => `Izvezeno stavki: ${count}.`,
    importTitle: 'Uvoz',
    importIntro:
      'Podržani su JSON izvoz iz SleepSafe-a i CSV iz drugih menadžera lozinki (Chrome, Bitwarden, 1Password, LastPass, KeePass). Stavke se šifruju u ovom pregledaču.',
    chooseFile: 'Izaberite fajl za uvoz',
    found: (count: number, skipped: number) =>
      skipped === 0
        ? `Pronađeno stavki: ${count}.`
        : `Pronađeno stavki: ${count}. Preskočeno zbog neispravnih podataka: ${skipped}.`,
    skipDuplicates: 'Preskoči stavke koje već postoje',
    importButton: (count: number) => `Uvezi ${count} stavki`,
    progress: (done: number, total: number) => `Uvezeno ${done} od ${total}…`,
    result: (created: number, failed: number, duplicates: number) =>
      `Uvezeno: ${created}. Neuspešno: ${failed}. Preskočeno kao duplikat: ${duplicates}.`,
    stoppedFull: 'Uvoz je prekinut: dostignut je najveći dozvoljeni broj stavki.',
    stoppedNetwork: 'Uvoz je prekinut: server nije dostupan. Ono što je uvezeno ostaje u vaultu.',
    stoppedLocked: 'Uvoz je prekinut jer je vault zaključan.',
  },

  errors: {
    importInvalid: 'Fajl se ne može pročitati (neispravan JSON ili CSV).',
    importUnknown: 'Oblik fajla nije prepoznat. Očekuje se SleepSafe JSON ili CSV sa kolonama.',
    importEmpty: 'U fajlu nema nijedne ispravne stavke.',
    importTooLarge: 'Fajl je prevelik (najviše 5 MB).',
    importTooMany: 'U fajlu ima previše stavki (najviše 10 000).',

    invalidEmail: 'Unesite ispravnu email adresu.',
    passwordTooShort: (min: number) => `Master lozinka mora imati najmanje ${min} znakova.`,
    passwordMismatch: 'Lozinke se ne poklapaju.',
    acknowledgeRequired: 'Potvrdite da razumete da se master lozinka ne može povratiti.',
    codeFormat: 'Kod ima tačno 6 cifara.',
    invalidCredentials: 'Pogrešan email ili lozinka.',
    wrongPassword: 'Pogrešna master lozinka.',
    invalidCode: 'Kod nije ispravan ili je istekao.',
    tooManyAttempts: 'Previše neuspelih pokušaja. Pokušajte ponovo za nekoliko minuta.',
    rateLimited: 'Previše zahteva. Sačekajte trenutak pa pokušajte ponovo.',
    validation: 'Uneti podaci nisu ispravni.',
    network: 'Server nije dostupan. Proverite vezu i pokušajte ponovo.',
    weakKdf:
      'Server je predložio preslabu zaštitu lozinke. Prijava je prekinuta radi vaše bezbednosti.',
    vaultCorrupt: 'Vault na serveru je oštećen i ne može se otvoriti.',
    itemConflict:
      'Stavka je u međuvremenu izmenjena ili obrisana na drugom uređaju. Prikazana je najnovija verzija.',
    itemNotFound: 'Stavka više ne postoji.',
    itemInvalid: 'Naslov je obavezan, a polja ne smeju biti predugačka.',
    itemTooLarge: 'Stavka je prevelika za čuvanje.',
    vaultFull: 'Dostignut je najveći dozvoljeni broj stavki.',
    generic: 'Došlo je do greške. Pokušajte ponovo.',
  },
} as const;
