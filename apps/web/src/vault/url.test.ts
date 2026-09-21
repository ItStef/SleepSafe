import { describe, expect, it } from 'vitest';
import { toSafeUrl } from './url';

describe('toSafeUrl', () => {
  it('prihvata http i https adrese', () => {
    expect(toSafeUrl('https://banka.example/prijava')).toBe('https://banka.example/prijava');
    expect(toSafeUrl('http://intranet.local')).toBe('http://intranet.local/');
    expect(toSafeUrl('HTTPS://Banka.Example')).toBe('https://banka.example/');
    expect(toSafeUrl('  https://banka.example  ')).toBe('https://banka.example/');
  });

  it('adresi bez seme dodaje https', () => {
    expect(toSafeUrl('banka.example')).toBe('https://banka.example/');
    expect(toSafeUrl('www.banka.example/x?y=1')).toBe('https://www.banka.example/x?y=1');
    expect(toSafeUrl('localhost:3000')).toBe('https://localhost:3000/');
    expect(toSafeUrl('192.168.0.1:8443/admin')).toBe('https://192.168.0.1:8443/admin');
  });

  it('odbija sheme koje izvrsavaju kod ili nisu web', () => {
    const bad = [
      'javascript:alert(1)',
      'JaVaScRiPt:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'vbscript:msgbox(1)',
      'file:///etc/passwd',
      'ftp://server.example',
      'mailto:marko@example.com',
      'blob:https://banka.example/abc',
    ];
    for (const value of bad) {
      expect(toSafeUrl(value), value).toBeNull();
    }
  });

  it('odbija prazan unos, adrese bez hosta i one sa korisnickim imenom u adresi', () => {
    expect(toSafeUrl('')).toBeNull();
    expect(toSafeUrl('   ')).toBeNull();
    expect(toSafeUrl('https://')).toBeNull();
    expect(toSafeUrl('nije adresa sa razmacima')).toBeNull();
    expect(toSafeUrl('https://google.com@lazan.example')).toBeNull();
    expect(toSafeUrl('https://korisnik:lozinka@banka.example')).toBeNull();
  });
});
