import type { Mail } from './mailer';

export type OtpEmailPurpose = 'LOGIN' | 'EMAIL_VERIFICATION';

const TEXTS: Record<OtpEmailPurpose, { subject: string; intro: string; ignore: string }> = {
  LOGIN: {
    subject: 'SleepSafe: kod za prijavu',
    intro: 'Vaš SleepSafe kod za prijavu je:',
    ignore:
      'Ako se niste vi prijavljivali, ignorišite ovu poruku i razmislite o promeni master lozinke.',
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
