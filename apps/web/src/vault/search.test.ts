import type { ItemData } from '@sleepsafe/shared';
import { describe, expect, it } from 'vitest';
import { filterEntries } from './search';
import type { VaultEntry } from './store';

const entry = (id: string, data: Partial<ItemData>): VaultEntry => ({
  id,
  revision: 1,
  updatedAt: '2026-01-01T00:00:00.000Z',
  data: { title: 'x', username: '', password: '', url: '', notes: '', ...data },
});

const entries = [
  entry('1', { title: 'Banka', username: 'marko.markovic', url: 'https://banka.example' }),
  entry('2', { title: 'Češir Mačak', notes: 'privatni nalog' }),
  entry('3', { title: 'Mail', username: 'marko@example.com', password: 'zlatna-ribica' }),
  entry('4', { title: 'Đurđevak', url: 'www.djurdjevak.rs' }),
];

const ids = (query: string) => filterEntries(entries, query).map((e) => e.id);

describe('filterEntries', () => {
  it('prazan upit (i samo razmaci) vraca sve, isti niz', () => {
    expect(filterEntries(entries, '')).toBe(entries);
    expect(filterEntries(entries, '   ')).toBe(entries);
  });

  it('trazi u naslovu, korisnickom imenu, adresi i beleskama, bez obzira na velika slova', () => {
    expect(ids('BANKA')).toEqual(['1']);
    expect(ids('marko')).toEqual(['1', '3']);
    expect(ids('example.com')).toEqual(['3']);
    expect(ids('privatni')).toEqual(['2']);
  });

  it('sve reci iz upita moraju da se poklope (bilo kojim redosledom)', () => {
    expect(ids('marko banka')).toEqual(['1']);
    expect(ids('banka marko')).toEqual(['1']);
    expect(ids('marko nepostojece')).toEqual([]);
  });

  it('ne razlikuje č, ć, š, ž, đ od c, s, z, d', () => {
    expect(ids('cesir macak')).toEqual(['2']);
    expect(ids('Češir')).toEqual(['2']);
    expect(ids('djurdjevak')).toEqual(['4']);
    expect(ids('đurđevak')).toEqual(['4']);
  });

  it('nikad ne pretrazuje lozinku', () => {
    expect(ids('zlatna')).toEqual([]);
    expect(ids('ribica')).toEqual([]);
  });
});
