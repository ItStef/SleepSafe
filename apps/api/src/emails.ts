import type { Mail } from './mailer';

export type OtpEmailPurpose = 'LOGIN' | 'EMAIL_VERIFICATION' | 'RECOVERY';

const TEXTS: Record<OtpEmailPurpose, { subject: string; intro: string; ignore: string }> = {
  LOGIN: {
    subject: 'SleepSafe: kod za prijavu',
    intro: 'Vaš SleepSafe kod za prijavu je:',
    ignore:
      'Ako se niste vi prijavljivali, ignorišite ovu poruku i razmislite o promeni master lozinke.',
  },
  RECOVERY: {
    subject: 'SleepSafe: kod za oporavak naloga',
    intro: 'Vaš SleepSafe kod za oporavak naloga je:',
    ignore:
      'Ako niste vi zatražili oporavak, ignorišite ovu poruku: bez vašeg koda za oporavak niko ne može da promeni lozinku.',
  },
  EMAIL_VERIFICATION: {
    subject: 'SleepSafe: potvrda email adrese',
    intro: 'Vaš SleepSafe kod za potvrdu email adrese je:',
    ignore: 'Ako niste vi kreirali nalog, ignorišite ovu poruku.',
  },
};

export function buildOtpEmail(
  to: string,
  code: string,
  purpose: OtpEmailPurpose,
  ttlMinutes: number,
): Mail {
  if (!/^\d{6}$/.test(code) || !Number.isInteger(ttlMinutes) || ttlMinutes < 1) {
    throw new Error('Invalid OTP email parameters');
  }
  const texts = TEXTS[purpose];
  const text = [
    texts.intro,
    '',
    `    ${code}`,
    '',
    `Kod važi ${ttlMinutes} min i može da se iskoristi samo jednom.`,
    '',
    texts.ignore,
    'Nikome ne otkrivajte ovaj kod: SleepSafe vas nikada neće tražiti da ga pošaljete.',
  ].join('\n');
  return { to, subject: texts.subject, text };
}
export type NoticeKind =
  'PASSWORD_CHANGED' | 'PASSWORD_RESET' | 'RECOVERY_CODES_CHANGED' | 'ACCOUNT_DELETED';

const NOTICES: Record<NoticeKind, { subject: string; lines: string[] }> = {
  PASSWORD_CHANGED: {
    subject: 'SleepSafe: master lozinka je promenjena',
    lines: [
      'Master lozinka vašeg SleepSafe naloga je upravo promenjena, a sve ostale prijavljene sesije su odjavljene.',
      '',
      'Ako ste to uradili vi, ne morate ništa da preduzimate.',
      'Ako niste, neko zna vašu staru lozinku i ima pristup vašem nalogu: odmah se prijavite i promenite lozinku.',
    ],
  },
  PASSWORD_RESET: {
    subject: 'SleepSafe: master lozinka je resetovana kodom za oporavak',
    lines: [
      'Master lozinka vašeg SleepSafe naloga je upravo promenjena pomoću koda za oporavak, a sve prijavljene sesije su odjavljene.',
      '',
      'Ako ste to uradili vi, ne morate ništa da preduzimate. Iskorišćeni kod više ne važi.',
      'Ako niste, neko ima vaš kod za oporavak i pristup vašem email nalogu: odmah se prijavite, promenite lozinku i napravite nove kodove za oporavak.',
    ],
  },
  RECOVERY_CODES_CHANGED: {
    subject: 'SleepSafe: napravljeni su novi kodovi za oporavak',
    lines: [
      'Za vaš SleepSafe nalog je upravo napravljen novi skup kodova za oporavak. Svi stari kodovi više ne važe.',
      '',
      'Ako niste vi to uradili, neko zna vašu master lozinku: odmah je promenite.',
    ],
  },
  ACCOUNT_DELETED: {
    subject: 'SleepSafe: nalog je obrisan',
    lines: [
      'Vaš SleepSafe nalog i svi šifrovani podaci u njemu su trajno obrisani sa servera.',
      '',
      'Ako niste vi to uradili, neko zna vašu lozinku. Podaci se ne mogu vratiti.',
    ],
  },
};

export function buildNoticeEmail(to: string, kind: NoticeKind): Mail {
  const notice = NOTICES[kind];
  return { to, subject: notice.subject, text: notice.lines.join('\n') };
}
