import { randomUUID } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { buildOtpEmail } from '../emails';
import { MemoryMailer, assertValidMail, createSmtpMailer } from '../mailer';

describe('assertValidMail', () => {
  const ok = { to: 'korisnik@example.com', subject: 'Naslov', text: 'Tekst' };

  it('prihvata obicnu poruku', () => {
    expect(() => assertValidMail(ok)).not.toThrow();
    expect(() => assertValidMail({ ...ok, to: 'ime.prezime+tag@sub.example.co.rs' })).not.toThrow();
  });

  it('odbija ubacivanje dodatnih zaglavlja kroz adresu ili naslov', () => {
    for (const to of [
      'a@example.com\r\nBcc: zlo@example.com',
      'a@example.com\nBcc: zlo@example.com',
      'a@example.com Bcc: zlo@example.com',
    ]) {
      expect(() => assertValidMail({ ...ok, to })).toThrow('Invalid mail');
    }
    expect(() => assertValidMail({ ...ok, subject: 'Naslov\r\nBcc: zlo@example.com' })).toThrow(
      'Invalid mail',
    );
  });

  it('odbija vise primalaca, imena u zagradama i neispravne adrese', () => {
    for (const to of [
      'a@example.com,b@example.com',
      'a@example.com;b@example.com',
      'Ime <a@example.com>',
      '"a b"@example.com',
      'bez-znaka-at',
      '@example.com',
      'a@',
      '',
      `${'a'.repeat(250)}@example.com`,
    ]) {
      expect(() => assertValidMail({ ...ok, to })).toThrow('Invalid mail');
    }
  });
});

describe('MemoryMailer', () => {
  it('pamti poslate poruke redom', async () => {
    const mailer = new MemoryMailer();
    await mailer.send({ to: 'a@example.com', subject: 'Prva', text: '1' });
    await mailer.send({ to: 'b@example.com', subject: 'Druga', text: '2' });
    expect(mailer.sent.map((mail) => mail.subject)).toEqual(['Prva', 'Druga']);
    expect(mailer.last?.to).toBe('b@example.com');
  });

  it('cuva kopiju: kasnija izmena originala ne menja zapamcenu poruku', async () => {
    const mailer = new MemoryMailer();
    const mail = { to: 'a@example.com', subject: 'Naslov', text: 'Tekst' };
    await mailer.send(mail);
    mail.text = 'IZMENJENO';
    expect(mailer.last?.text).toBe('Tekst');
  });

  it('primenjuje ista pravila kao pravi mailer', async () => {
    const mailer = new MemoryMailer();
    await expect(
      mailer.send({ to: 'a@example.com\nBcc: zlo@example.com', subject: 'x', text: 'x' }),
    ).rejects.toThrow('Invalid mail');
    expect(mailer.sent).toHaveLength(0);
  });
});

const uiPort = process.env['MAILPIT_UI_PORT'];
const smtpPort = process.env['MAILPIT_SMTP_PORT'];

interface MailpitMessageSummary {
  ID: string;
  Subject: string;
  To: { Address: string }[];
}

interface MailpitMessage {
  From: { Address: string };
  To: { Address: string }[];
  Bcc: { Address: string }[];
  Subject: string;
  Text: string;
}

describe.skipIf(!uiPort || !smtpPort)('SMTP: stvarna dostava preko Mailpit-a', () => {
  const api = `http://127.0.0.1:${uiPort}/api/v1`;
  const mailer = createSmtpMailer({
    SMTP_HOST: '127.0.0.1',
    SMTP_PORT: Number(smtpPort),
    SMTP_TLS: 'none',
    SMTP_USER: undefined,
    SMTP_PASS: undefined,
    SMTP_FROM: 'SleepSafe <no-reply@sleepsafe.test>',
  });
  const createdIds: string[] = [];

  async function listMessages(): Promise<MailpitMessageSummary[]> {
    const response = await fetch(`${api}/messages?limit=200`);
    const body = (await response.json()) as { messages: MailpitMessageSummary[] };
    return body.messages;
  }

  async function findByRecipient(address: string): Promise<MailpitMessageSummary | undefined> {
    const found = (await listMessages()).find((message) =>
      message.To.some((to) => to.Address === address),
    );
    if (found) {
      createdIds.push(found.ID);
    }
    return found;
  }

  async function readMessage(id: string): Promise<MailpitMessage> {
    const response = await fetch(`${api}/message/${id}`);
    return (await response.json()) as MailpitMessage;
  }

  afterAll(async () => {
    if (createdIds.length > 0) {
      await fetch(`${api}/messages`, {
        method: 'DELETE',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ IDs: createdIds }),
      });
    }
  });

  it('dostavlja poruku sa tacnim primaocem, posiljaocem, naslovom i srpskim slovima', async () => {
    const to = `dostava-${randomUUID()}@example.com`;
    const text = 'Zdravo, šđčćž ŠĐČĆŽ. Kod: 123456';
    await mailer.send({ to, subject: 'Probni naslov: šđčćž', text });

    const summary = await findByRecipient(to);
    expect(summary).toBeDefined();
    const message = await readMessage((summary as MailpitMessageSummary).ID);
    expect(message.From.Address).toBe('no-reply@sleepsafe.test');
    expect(message.To.map((recipient) => recipient.Address)).toEqual([to]);
    expect(message.Subject).toBe('Probni naslov: šđčćž');
    expect(message.Text).toContain(text);
  });

  it('OTP poruka stize sa kodom u tekstu', async () => {
    const to = `otp-${randomUUID()}@example.com`;
    await mailer.send(buildOtpEmail(to, '482913', 'LOGIN', 10));

    const summary = await findByRecipient(to);
    expect(summary).toBeDefined();
    const message = await readMessage((summary as MailpitMessageSummary).ID);
    expect(message.Subject).toBe('SleepSafe: kod za prijavu');
    expect(message.Text).toContain('482913');
    expect(message.Text).toContain('10 min');
  });

  it('pokusaj ubacivanja skrivenog primaoca se odbija i nista se ne salje', async () => {
    const id = randomUUID();
    const victim = `zrtva-${id}@example.com`;
    await expect(
      mailer.send({ to: `${victim}\r\nBcc: zlo-${id}@example.com`, subject: 'x', text: 'x' }),
    ).rejects.toThrow('Invalid mail');

    const all = await listMessages();
    const leaked = all.filter((message) => message.To.some((to) => to.Address.includes(id)));
    expect(leaked).toHaveLength(0);
  });

  it('prijavljuje gresku kada email server nije dostupan', async () => {
    const unreachable = createSmtpMailer({
      SMTP_HOST: '127.0.0.1',
      SMTP_PORT: 1,
      SMTP_TLS: 'none',
      SMTP_USER: undefined,
      SMTP_PASS: undefined,
      SMTP_FROM: 'SleepSafe <no-reply@sleepsafe.test>',
    });
    await expect(
      unreachable.send({ to: 'a@example.com', subject: 'x', text: 'x' }),
    ).rejects.toThrow();
  });
});
