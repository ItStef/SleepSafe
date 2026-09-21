import { encryptItem } from '@sleepsafe/crypto';
import { type ItemData, itemEnvelopeSchema } from '@sleepsafe/shared';
import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { App } from '../App';
import { AuthProvider } from '../auth/context';
import { AuthStore } from '../auth/store';
import { inlineDeriver } from '../crypto/deriver';
import { FakeServer, TEST_KDF } from '../test/fakeServer';
import { IDLE_LOCK_MS, SYNC_INTERVAL_MS } from '../vault/hooks';

const EMAIL = 'korisnik@example.com';
const PASSWORD = 'moja dugacka master lozinka';

const data = (title: string, extra: Partial<ItemData> = {}): ItemData => ({
  title,
  username: 'marko',
  password: 'tajna-lozinka-123',
  url: '',
  notes: '',
  ...extra,
});

describe('VaultScreen', () => {
  let template: FakeServer;
  let userId: string;
  let vaultKey: CryptoKey;

  beforeAll(async () => {
    template = new FakeServer();
    ({ id: userId, vaultKey } = await template.seedUser(EMAIL, PASSWORD));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // Stavka koju je drugi uredjaj vec upisao na server.
  async function seed(server: FakeServer, item: ItemData, id: string = crypto.randomUUID()) {
    const envelope = itemEnvelopeSchema.parse(
      await encryptItem(vaultKey, item, { userId, itemId: id }),
    );
    const { revision } = server.putAsOtherDevice(userId, id, { envelope, baseRevision: null });
    return { id, revision };
  }

  async function open(
    options: {
      before?: (server: FakeServer) => unknown;
      timers?: boolean;
    } = {},
  ) {
    const server = new FakeServer();
    for (const [email, user] of template.users) server.users.set(email, user);
    server.startSession(EMAIL);
    await options.before?.(server);
    const store = new AuthStore({
      api: server,
      vaultApi: server,
      deriver: inlineDeriver,
      kdfParams: TEST_KDF,
    });
    await store.boot();
    if (options.timers) vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup(
      options.timers ? { advanceTimers: (ms) => void vi.advanceTimersByTime(ms) } : {},
    );
    // Sopstveni klipbord umesto onog iz user-event-a: cita se onako kako ga vidi stranica.
    const clipboard = {
      text: null as string | null,
      async writeText(text: string) {
        this.text = text;
      },
    };
    Object.defineProperty(navigator, 'clipboard', { value: clipboard, configurable: true });
    render(
      <AuthProvider store={store}>
        <App />
      </AuthProvider>,
    );
    await user.type(screen.getByLabelText(/^master lozinka$/i), PASSWORD);
    await user.click(screen.getByRole('button', { name: /^otključaj$/i }));
    await screen.findByRole('heading', { name: /vaš vault/i });
    return { server, store, user, clipboard };
  }

  const button = (name: RegExp) => screen.getByRole('button', { name });
  const entryNames = () =>
    within(screen.getByRole('list'))
      .getAllByRole('button')
      .map((entry) => entry.textContent);
  const field = (name: RegExp) => screen.getByLabelText(name);

  async function fillForm(user: ReturnType<typeof userEvent.setup>, values: Partial<ItemData>) {
    if (values.title !== undefined) await user.type(field(/^naslov$/i), values.title);
    if (values.username !== undefined) await user.type(field(/korisničko ime/i), values.username);
    if (values.password !== undefined) await user.type(field(/^lozinka$/i), values.password);
    if (values.url !== undefined) await user.type(field(/^adresa$/i), values.url);
    if (values.notes !== undefined) await user.type(field(/beleške/i), values.notes);
  }

  describe('lista', () => {
    it('prazan vault: poruka i dugme za novu stavku', async () => {
      await open();
      expect(await screen.findByText(/vault je prazan/i)).toBeInTheDocument();
      expect(button(/nova stavka/i)).toBeInTheDocument();
    });

    it('prikazuje stavke sortirano po naslovu, sa korisnickim imenom ili adresom ispod naslova', async () => {
      await open({
        before: async (server) => {
          await seed(server, data('Mail'));
          await seed(server, data('Banka', { username: '', url: 'banka.example' }));
        },
      });
      await screen.findByRole('list');
      expect(entryNames()).toEqual(['Bankabanka.example', 'Mailmarko']);
      expect(screen.getByText(/stavki: 2/i)).toBeInTheDocument();
    });

    it('lozinke nema nigde u listi', async () => {
      await open({ before: (server) => seed(server, data('Banka')) });
      await screen.findByRole('list');
      expect(screen.queryByText(/tajna-lozinka-123/)).not.toBeInTheDocument();
    });

    it('pretraga sužava listu, ne pretražuje lozinku i javlja kad nema rezultata', async () => {
      const { user } = await open({
        before: async (server) => {
          await seed(server, data('Banka'));
          await seed(server, data('Mail'));
        },
      });
      await screen.findByRole('list');

      await user.type(field(/pretraga/i), 'ban');
      expect(entryNames()).toEqual(['Bankamarko']);
      expect(screen.getByText(/prikazano 1 od 2/i)).toBeInTheDocument();

      await user.clear(field(/pretraga/i));
      await user.type(field(/pretraga/i), 'tajna-lozinka');
      expect(screen.getByText(/nema rezultata/i)).toBeInTheDocument();
      expect(screen.queryByRole('list')).not.toBeInTheDocument();
    });

    it('greska pri ucitavanju: poruka i ponovni pokusaj', async () => {
      const { server, user } = await open({
        before: (server) => {
          server.failing.add('vault.list');
        },
      });
      expect(await screen.findByRole('alert')).toHaveTextContent(/stavke nisu učitane/i);
      expect(screen.getByRole('alert')).toHaveTextContent(/server nije dostupan/i);

      server.failing.clear();
      await seed(server, data('Banka'));
      await user.click(button(/pokušaj ponovo/i));
      expect(await screen.findByRole('list')).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('stavke koje se ne mogu otvoriti su prijavljene, a ostale se prikazuju', async () => {
      await open({
        before: async (server) => {
          await seed(server, data('Ispravna'));
          const foreign = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
            'encrypt',
            'decrypt',
          ]);
          const id = crypto.randomUUID();
          server.putAsOtherDevice(userId, id, {
            envelope: itemEnvelopeSchema.parse(
              await encryptItem(foreign, data('tudja'), { userId, itemId: id }),
            ),
            baseRevision: null,
          });
        },
      });
      expect(await screen.findByText(/1 stavka se ne može otvoriti/i)).toBeInTheDocument();
      expect(entryNames()).toEqual(['Ispravnamarko']);
    });
  });

  describe('prikaz stavke', () => {
    it('lozinka je sakrivena dok se ne prikaze, i moze ponovo da se sakrije', async () => {
      const { user } = await open({ before: (server) => seed(server, data('Banka')) });
      await user.click(await screen.findByRole('button', { name: /banka/i }));

      expect(screen.getByRole('heading', { name: 'Banka' })).toBeInTheDocument();
      expect(screen.queryByText('tajna-lozinka-123')).not.toBeInTheDocument();
      expect(screen.getByText(/sakrivena/i)).toBeInTheDocument();

      await user.click(button(/^prikaži$/i));
      expect(screen.getByText('tajna-lozinka-123')).toBeInTheDocument();
      await user.click(button(/^sakrij$/i));
      expect(screen.queryByText('tajna-lozinka-123')).not.toBeInTheDocument();
    });

    it('bezbedna adresa je link koji ne otkriva stranicu, a "javascript:" nije link', async () => {
      const { user } = await open({
        before: async (server) => {
          await seed(server, data('Dobra', { url: 'banka.example' }));
          await seed(server, data('Losa', { url: 'javascript:alert(1)' }));
        },
      });
      await user.click(await screen.findByRole('button', { name: /dobra/i }));
      const link = screen.getByRole('link', { name: 'banka.example' });
      expect(link).toHaveAttribute('href', 'https://banka.example/');
      expect(link).toHaveAttribute('target', '_blank');
      expect(link.getAttribute('rel')).toContain('noopener');
      expect(link.getAttribute('rel')).toContain('noreferrer');

      await user.click(button(/^nazad$/i));
      await user.click(screen.getByRole('button', { name: /losa/i }));
      expect(screen.queryByRole('link')).not.toBeInTheDocument();
      expect(screen.getByText('javascript:alert(1)')).toBeInTheDocument();
      expect(screen.getByText(/ne otvara kao link/i)).toBeInTheDocument();
    });

    it('stavka obrisana na drugom uredjaju vraca na listu', async () => {
      const seeded = { id: '' };
      const { server, user } = await open({
        before: async (server) => {
          seeded.id = (await seed(server, data('Nestaje'))).id;
          await seed(server, data('Ostaje'));
        },
      });
      await user.click(await screen.findByRole('button', { name: /nestaje/i }));
      server.removeAsOtherDevice(userId, seeded.id);

      await act(async () => {
        window.dispatchEvent(new Event('focus'));
      });
      expect(await screen.findByRole('list')).toBeInTheDocument();
      expect(entryNames()).toEqual(['Ostajemarko']);
    });
  });

  describe('nova stavka i izmena', () => {
    it('cuva novu stavku sifrovanu, pa je prikazuje; bez naslova dugme je onemoguceno', async () => {
      const { server, user } = await open();
      await user.click(await screen.findByRole('button', { name: /nova stavka/i }));

      expect(button(/sačuvaj/i)).toBeDisabled();
      await fillForm(user, {
        title: 'Banka',
        username: 'marko',
        password: 'veoma-tajna-lozinka',
        url: 'banka.example',
        notes: 'beleska',
      });
      await user.click(button(/sačuvaj/i));

      expect(await screen.findByRole('heading', { name: 'Banka' })).toBeInTheDocument();
      const [put] = server.callsTo('vault.put');
      expect(server.callsTo('vault.put')).toHaveLength(1);
      const sent = JSON.stringify(put?.args);
      for (const secret of ['Banka', 'marko', 'veoma-tajna-lozinka', 'banka.example', 'beleska']) {
        expect(sent).not.toContain(secret);
      }

      await user.click(button(/^nazad$/i));
      expect(entryNames()).toEqual(['Bankamarko']);
    });

    it('neispravan unos iz forme daje poruku, ne salje nista', async () => {
      const { server, user } = await open();
      await user.click(await screen.findByRole('button', { name: /nova stavka/i }));
      await user.type(field(/^naslov$/i), '   ');
      expect(button(/sačuvaj/i)).toBeDisabled();
      expect(server.callsTo('vault.put')).toHaveLength(0);
    });

    it('izmena koristi trenutnu reviziju i odmah se vidi', async () => {
      const { server, user } = await open({ before: (server) => seed(server, data('Banka')) });
      await user.click(await screen.findByRole('button', { name: /banka/i }));
      await user.click(button(/^izmeni$/i));

      expect(field(/^naslov$/i)).toHaveValue('Banka');
      await user.clear(field(/^naslov$/i));
      await user.type(field(/^naslov$/i), 'Banka 2');
      await user.click(button(/sačuvaj/i));

      expect(await screen.findByRole('heading', { name: 'Banka 2' })).toBeInTheDocument();
      const [put] = server.callsTo('vault.put');
      expect((put?.args as { body: { baseRevision: number } }).body.baseRevision).toBe(1);
    });

    it('odustajanje od izmene ne salje nista', async () => {
      const { server, user } = await open({ before: (server) => seed(server, data('Banka')) });
      await user.click(await screen.findByRole('button', { name: /banka/i }));
      await user.click(button(/^izmeni$/i));
      await user.type(field(/^naslov$/i), ' izmena');
      await user.click(button(/^odustani$/i));
      expect(screen.getByRole('heading', { name: 'Banka' })).toBeInTheDocument();
      expect(server.callsTo('vault.put')).toHaveLength(0);
    });

    it('konflikt: poruka, zadrzan unos, a ponovno cuvanje posle osvezavanja uspeva', async () => {
      const seeded = { id: '', revision: 0 };
      const { server, user } = await open({
        before: async (server) => {
          Object.assign(seeded, await seed(server, data('Banka')));
        },
      });
      await user.click(await screen.findByRole('button', { name: /banka/i }));
      await user.click(button(/^izmeni$/i));

      // Dok je forma otvorena, drugi uredjaj menja istu stavku.
      const envelope = itemEnvelopeSchema.parse(
        await encryptItem(vaultKey, data('Banka sa telefona'), { userId, itemId: seeded.id }),
      );
      server.putAsOtherDevice(userId, seeded.id, { envelope, baseRevision: seeded.revision });

      await user.clear(field(/^naslov$/i));
      await user.type(field(/^naslov$/i), 'Moja izmena');
      await user.click(button(/sačuvaj/i));

      expect(await screen.findByRole('alert')).toHaveTextContent(/izmenjena ili obrisana/i);
      expect(field(/^naslov$/i)).toHaveValue('Moja izmena');

      await user.click(button(/sačuvaj/i));
      expect(await screen.findByRole('heading', { name: 'Moja izmena' })).toBeInTheDocument();
    });
  });

  describe('brisanje', () => {
    it('trazi potvrdu, odustajanje ne brise, potvrda brise i na serveru', async () => {
      const { server, user } = await open({
        before: async (server) => {
          await seed(server, data('Banka'));
          await seed(server, data('Mail'));
        },
      });
      await user.click(await screen.findByRole('button', { name: /banka/i }));

      await user.click(button(/^obriši$/i));
      expect(screen.getByRole('alert')).toHaveTextContent(/trajno obrisati „banka“/i);
      await user.click(button(/^odustani$/i));
      expect(server.callsTo('vault.remove')).toHaveLength(0);

      await user.click(button(/^obriši$/i));
      await user.click(button(/da, obriši/i));

      expect(await screen.findByRole('list')).toBeInTheDocument();
      expect(entryNames()).toEqual(['Mailmarko']);
      expect(server.callsTo('vault.remove')).toHaveLength(1);
    });

    it('mrezna greska pri brisanju: poruka, stavka ostaje', async () => {
      const { server, user } = await open({ before: (server) => seed(server, data('Banka')) });
      await user.click(await screen.findByRole('button', { name: /banka/i }));
      await user.click(button(/^obriši$/i));
      server.failing.add('vault.remove');
      await user.click(button(/da, obriši/i));
      expect(await screen.findAllByRole('alert')).not.toHaveLength(0);
      expect(screen.getByText(/server nije dostupan/i)).toBeInTheDocument();
      expect(screen.getByRole('heading', { name: 'Banka' })).toBeInTheDocument();
    });
  });

  describe('generator lozinki', () => {
    async function openGenerator(user: ReturnType<typeof userEvent.setup>) {
      await user.click(await screen.findByRole('button', { name: /nova stavka/i }));
      await user.click(button(/generator lozinki/i));
    }
    const suggestion = () => screen.getByTestId('generated-password').textContent ?? '';

    it('predlaze lozinku podrazumevane duzine i ubacuje je u polje', async () => {
      const { user } = await open();
      await openGenerator(user);

      const proposed = suggestion();
      expect(proposed).toHaveLength(20);
      await user.click(button(/koristi ovu lozinku/i));

      expect(screen.queryByTestId('generated-password')).not.toBeInTheDocument();
      expect(field(/^lozinka$/i)).toHaveValue(proposed);
    });

    it('promena duzine i grupa menja predlog, a neispravne postavke onemogucavaju upotrebu', async () => {
      const { user } = await open();
      await openGenerator(user);

      const length = field(/dužina/i);
      await user.clear(length);
      expect(screen.getByRole('alert')).toHaveTextContent(/od 8 do 128/i);
      expect(button(/koristi ovu lozinku/i)).toBeDisabled();
      await user.type(length, '12');
      expect(suggestion()).toHaveLength(12);

      await user.click(field(/mala slova/i));
      await user.click(field(/velika slova/i));
      await user.click(field(/cifre/i));
      await user.click(field(/simboli/i));
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(button(/nova lozinka/i)).toBeDisabled();

      await user.click(field(/cifre/i));
      expect(suggestion()).toMatch(/^[0-9]{12}$/);
    });

    it('"Nova lozinka" pravi drugu lozinku', async () => {
      const { user } = await open();
      await openGenerator(user);
      const first = suggestion();
      await user.click(button(/nova lozinka/i));
      expect(suggestion()).not.toBe(first);
    });
  });

  describe('klipbord', () => {
    it('lozinka se kopira i brise posle 30 sekundi, korisnicko ime ostaje', async () => {
      const { user, clipboard } = await open({
        timers: true,
        before: (server) => seed(server, data('Banka')),
      });
      await user.click(await screen.findByRole('button', { name: /banka/i }));

      await user.click(button(/kopiraj korisničko ime/i));
      expect(clipboard.text).toBe('marko');
      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(clipboard.text).toBe('marko');

      await user.click(button(/kopiraj lozinku/i));
      expect(clipboard.text).toBe('tajna-lozinka-123');
      expect(screen.getByRole('status')).toHaveTextContent(/briše za 30 sekundi/i);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(29_000);
      });
      expect(clipboard.text).toBe('tajna-lozinka-123');
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1_000);
      });
      expect(clipboard.text).toBe('');
    });

    it('zakljucavanje odmah brise kopiranu lozinku', async () => {
      const { user, clipboard } = await open({
        timers: true,
        before: (server) => seed(server, data('Banka')),
      });
      await user.click(await screen.findByRole('button', { name: /banka/i }));
      await user.click(button(/kopiraj lozinku/i));
      expect(clipboard.text).toBe('tajna-lozinka-123');

      await user.click(button(/^zaključaj$/i));
      expect(
        await screen.findByRole('heading', { name: /otključajte vault/i }),
      ).toBeInTheDocument();
      expect(clipboard.text).toBe('');
    });

    it('ako pregledac odbije kopiranje, korisnik dobija poruku', async () => {
      const { user } = await open({ before: (server) => seed(server, data('Banka')) });
      await user.click(await screen.findByRole('button', { name: /banka/i }));
      vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValueOnce(new Error('denied'));
      await user.click(button(/kopiraj lozinku/i));
      expect(await screen.findByRole('alert')).toHaveTextContent(/kopiranje nije uspelo/i);
    });
  });

  describe('zakljucavanje i osvezavanje', () => {
    it('dugme "Zakljucaj" vraca na otkljucavanje i u ekranu nema stavki', async () => {
      const { user } = await open({ before: (server) => seed(server, data('Banka')) });
      await screen.findByRole('list');
      await user.click(button(/^zaključaj$/i));
      expect(
        await screen.findByRole('heading', { name: /otključajte vault/i }),
      ).toBeInTheDocument();
      expect(screen.queryByText('Banka')).not.toBeInTheDocument();
      expect(document.body.textContent).not.toContain('tajna-lozinka-123');
    });

    it('posle 5 minuta bez aktivnosti zakljucava, a aktivnost odlaze zakljucavanje', async () => {
      await open({ timers: true });
      const advance = (ms: number) =>
        act(async () => {
          await vi.advanceTimersByTimeAsync(ms);
        });

      await advance(IDLE_LOCK_MS - 60_000);
      expect(screen.getByRole('heading', { name: /vaš vault/i })).toBeInTheDocument();

      act(() => {
        window.dispatchEvent(new Event('keydown'));
      });
      await advance(IDLE_LOCK_MS - 60_000);
      expect(screen.getByRole('heading', { name: /vaš vault/i })).toBeInTheDocument();

      await advance(60_000);
      expect(
        await screen.findByRole('heading', { name: /otključajte vault/i }),
      ).toBeInTheDocument();
    });

    it('povratak na karticu posle dugog odsustva zakljucava odmah (tajmeri u pozadini kasne)', async () => {
      await open({ timers: true });
      act(() => {
        vi.setSystemTime(Date.now() + IDLE_LOCK_MS + 1_000);
        document.dispatchEvent(new Event('visibilitychange'));
      });
      expect(
        await screen.findByRole('heading', { name: /otključajte vault/i }),
      ).toBeInTheDocument();
    });

    it('povratak na karticu posle kratkog odsustva ne zakljucava', async () => {
      await open({ timers: true });
      act(() => {
        vi.setSystemTime(Date.now() + IDLE_LOCK_MS - 60_000);
        document.dispatchEvent(new Event('visibilitychange'));
      });
      expect(screen.getByRole('heading', { name: /vaš vault/i })).toBeInTheDocument();
    });

    it('ne osvezava dok je kartica sakrivena', async () => {
      const { server } = await open({ timers: true });
      expect(await screen.findByText(/vault je prazan/i)).toBeInTheDocument();
      const listed = () => server.callsTo('vault.list').length;
      const before = listed();
      const advance = (ms: number) =>
        act(async () => {
          await vi.advanceTimersByTimeAsync(ms);
        });

      Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
      try {
        await advance(SYNC_INTERVAL_MS * 2);
        expect(listed()).toBe(before);
      } finally {
        delete (document as unknown as Record<string, unknown>)['visibilityState'];
      }
      await advance(SYNC_INTERVAL_MS);
      expect(listed()).toBeGreaterThan(before);
    });

    it('posle zakljucavanja se vise ne osvezava i ne broji neaktivnost', async () => {
      const { server, user } = await open({ timers: true });
      await user.click(button(/^zaključaj$/i));
      await screen.findByRole('heading', { name: /otključajte vault/i });
      // Ni tajmeri ekrana (neaktivnost, osvezavanje, klipbord) ne ostaju da rade u praznom hodu.
      expect(vi.getTimerCount()).toBe(0);
      const listed = server.callsTo('vault.list').length;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS * 2);
        window.dispatchEvent(new Event('focus'));
      });
      expect(server.callsTo('vault.list')).toHaveLength(listed);
      expect(screen.getByRole('heading', { name: /otključajte vault/i })).toBeInTheDocument();
    });

    it('stavka obrisana dok je forma za izmenu otvorena: povratak na listu, ne nova stavka', async () => {
      const seeded = { id: '' };
      const { server, user } = await open({
        before: async (server) => {
          seeded.id = (await seed(server, data('Nestaje'))).id;
        },
      });
      await user.click(await screen.findByRole('button', { name: /nestaje/i }));
      await user.click(button(/^izmeni$/i));
      expect(screen.getByRole('heading', { name: /izmena stavke/i })).toBeInTheDocument();

      server.removeAsOtherDevice(userId, seeded.id);
      await act(async () => {
        window.dispatchEvent(new Event('focus'));
      });
      expect(await screen.findByText(/vault je prazan/i)).toBeInTheDocument();
      expect(screen.queryByRole('heading', { name: /izmena stavke/i })).not.toBeInTheDocument();
    });

    it('povlaci promene sa drugih uredjaja na svaki minut', async () => {
      const { server } = await open({ timers: true });
      expect(await screen.findByText(/vault je prazan/i)).toBeInTheDocument();
      await seed(server, data('Sa telefona'));

      await act(async () => {
        await vi.advanceTimersByTimeAsync(SYNC_INTERVAL_MS);
      });
      expect(await screen.findByRole('button', { name: /sa telefona/i })).toBeInTheDocument();
    });

    it('povlaci promene i kad se vratite na karticu (fokus)', async () => {
      const { server } = await open();
      expect(await screen.findByText(/vault je prazan/i)).toBeInTheDocument();
      await seed(server, data('Sa telefona'));

      await act(async () => {
        window.dispatchEvent(new Event('focus'));
      });
      expect(await screen.findByRole('button', { name: /sa telefona/i })).toBeInTheDocument();
    });

    it('neuspelo osvezavanje: stavke ostaju, poruka nestaje kad prodje', async () => {
      const { server, user } = await open({
        before: (server) => seed(server, data('Banka')),
      });
      await screen.findByRole('list');

      server.failing.add('vault.list');
      await act(async () => {
        window.dispatchEvent(new Event('focus'));
      });
      expect(await screen.findByText(/osvežavanje nije uspelo/i)).toBeInTheDocument();
      expect(entryNames()).toEqual(['Bankamarko']);

      server.failing.clear();
      await user.click(button(/pokušaj ponovo/i));
      expect(screen.queryByText(/osvežavanje nije uspelo/i)).not.toBeInTheDocument();
    });
  });
});
