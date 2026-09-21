import nodemailer from 'nodemailer';
import type { Config } from './config';

export interface Mail {
  to: string;
  subject: string;
  text: string;
}

export interface Mailer {
  send(mail: Mail): Promise<void>;
}

const SINGLE_ADDRESS = /^[^\s@<>()[\]",;:\\]+@[^\s@<>()[\]",;:\\]+$/;
const MAX_ADDRESS_LENGTH = 254;

export function assertValidMail(mail: Mail): void {
  if (
    mail.to.length > MAX_ADDRESS_LENGTH ||
    !SINGLE_ADDRESS.test(mail.to) ||
    /[\r\n]/.test(mail.subject)
  ) {
    throw new Error('Invalid mail');
  }
}

type SmtpSettings = Pick<
  Config,
  'SMTP_HOST' | 'SMTP_PORT' | 'SMTP_TLS' | 'SMTP_USER' | 'SMTP_PASS' | 'SMTP_FROM'
>;

export function createSmtpMailer(smtp: SmtpSettings): Mailer {
  const transport = nodemailer.createTransport({
    host: smtp.SMTP_HOST,
    port: smtp.SMTP_PORT,
    secure: smtp.SMTP_TLS === 'tls',
    requireTLS: smtp.SMTP_TLS === 'starttls',
    ignoreTLS: smtp.SMTP_TLS === 'none',
    ...(smtp.SMTP_USER !== undefined && smtp.SMTP_PASS !== undefined
      ? { auth: { user: smtp.SMTP_USER, pass: smtp.SMTP_PASS } }
      : {}),
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
  });

  return {
    async send(mail) {
      assertValidMail(mail);
      await transport.sendMail({
        from: smtp.SMTP_FROM,
        to: mail.to,
        subject: mail.subject,
        text: mail.text,
      });
    },
  };
}
