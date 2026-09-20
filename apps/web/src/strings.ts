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
  },

  login: {
    title: 'Prijava',
    submit: 'Prijavi se',
    working: 'Izvodim ključeve…',
  },

  register: {
    title: 'Napravite nalog',
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

  home: {
    title: 'Vault je otključan',
    body: 'Stavke vaulta stižu u sledećem koraku.',
    lock: 'Zaključaj',
    logout: 'Odjavi se',
    signedInAs: (email: string) => `Prijavljeni ste kao ${email}`,
  },

  errors: {
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
    generic: 'Došlo je do greške. Pokušajte ponovo.',
  },
} as const;
