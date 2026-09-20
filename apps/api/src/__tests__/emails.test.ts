import { describe, expect, it } from 'vitest';
import { buildNoticeEmail, buildOtpEmail } from '../emails';

describe('buildOtpEmail', () => {
  it('poruka za prijavu sadrzi kod, rok i upozorenje', () => {
    const mail = buildOtpEmail('korisnik@example.com', '482913', 'LOGIN', 10);
    expect(mail.to).toBe('korisnik@example.com');
    expect(mail.subject).toBe('SleepSafe: kod za prijavu');
    expect(mail.text).toContain('482913');
    expect(mail.text).toContain('10 min');
    expect(mail.text).toContain('samo jednom');
    expect(mail.text).toContain('Nikome ne otkrivajte');
  });

  it('poruka za potvrdu adrese ima drugaciji naslov i tekst', () => {
    const mail = buildOtpEmail('korisnik@example.com', '000123', 'EMAIL_VERIFICATION', 15);
    expect(mail.subject).toBe('SleepSafe: potvrda email adrese');
    expect(mail.text).toContain('potvrdu email adrese');
    expect(mail.text).toContain('000123'); // vodece nule se cuvaju
    expect(mail.text).toContain('15 min');
  });

  it('nema linkova ni HTML-a (nista na sta bi se moglo kliknuti)', () => {
    for (const purpose of ['LOGIN', 'EMAIL_VERIFICATION'] as const) {
      const { text, subject } = buildOtpEmail('a@example.com', '123456', purpose, 10);
      for (const part of [text, subject]) {
        expect(part).not.toMatch(/https?:|www\.|<[a-z/]/i);
      }
    }
  });

  it('odbija kod koji nije tacno 6 cifara i neispravan rok', () => {
    const build = (code: string, ttl: number) => () =>
      buildOtpEmail('a@example.com', code, 'LOGIN', ttl);
    expect(build('12345', 10)).toThrow('Invalid OTP email parameters');
    expect(build('1234567', 10)).toThrow('Invalid OTP email parameters');
    expect(build('12345a', 10)).toThrow('Invalid OTP email parameters');
    expect(build('123456', 0)).toThrow('Invalid OTP email parameters');
    expect(build('123456', 1.5)).toThrow('Invalid OTP email parameters');
  });
});

describe('buildNoticeEmail', () => {
  it('obavestenje o promeni lozinke ima naslov, adresu i savet', () => {
    const mail = buildNoticeEmail('korisnik@example.com', 'PASSWORD_CHANGED');
    expect(mail.to).toBe('korisnik@example.com');
    expect(mail.subject).toBe('SleepSafe: master lozinka je promenjena');
    expect(mail.text).toContain('promenjena');
    expect(mail.text).toContain('Ako niste');
  });

  it('obavestenje o brisanju naloga kaze da se podaci ne mogu vratiti', () => {
    const mail = buildNoticeEmail('korisnik@example.com', 'ACCOUNT_DELETED');
    expect(mail.subject).toBe('SleepSafe: nalog je obrisan');
    expect(mail.text).toContain('trajno obrisani');
    expect(mail.text).toContain('ne mogu vratiti');
  });

  it('nema koda, linkova ni HTML-a', () => {
    for (const kind of ['PASSWORD_CHANGED', 'ACCOUNT_DELETED'] as const) {
      const { text, subject } = buildNoticeEmail('a@example.com', kind);
      expect(text).not.toMatch(/\b\d{6}\b/);
      for (const part of [text, subject]) {
        expect(part).not.toMatch(/https?:|www\.|<[a-z/]/i);
      }
    }
  });
});
