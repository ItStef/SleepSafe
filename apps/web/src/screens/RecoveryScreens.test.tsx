import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { App } from '../App';
import { AuthProvider } from '../auth/context';
import { AuthStore } from '../auth/store';
import { inlineDeriver } from '../crypto/deriver';
import { CODE, FakeServer, TEST_KDF } from '../test/fakeServer';
import { CLIPBOARD_CLEAR_MS } from '../vault/clipboard';

const EMAIL = 'korisnik@example.com';
const PASSWORD = 'moja dugacka master lozinka';
const NEW_PASSWORD = 'potpuno nova master lozinka';
const CODE_SHAPE = /^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/;

describe('kodovi za oporavak (ekrani)', () => {
  let template: FakeServer;
  let codes: string[];

  beforeAll(async () => {
    template = new FakeServer();
    await template.seedUser(EMAIL, PASSWORD);
    codes = await template.seedRecovery(EMAIL, 3);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  async function open(options: { seeded?: boolean; timers?: boolean } = {}) {
    const server = new FakeServer();
    if (options.seeded) {
      for (const [email, user] of template.users) server.users.set(email, structuredClone(user));
    }
    const store = new AuthStore({
      api: server,
      vaultApi: server,
      deriver: inlineDeriver,
      kdfParams: TEST_KDF,
      recoveryCodeCount: 3,
    });
    await store.boot();
    if (options.timers) vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup(
      options.timers ? { advanceTimers: (ms) => void vi.advanceTimersByTime(ms) } : {},
    );
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
    return { server, store, user, clipboard };
  }

  const button = (name: RegExp) => screen.getByRole('button', { name });
  const field = (name: RegExp) => screen.getByLabelText(name);

  async function register(user: ReturnType<typeof userEvent.setup>, email = 'nov@example.com') {
    await user.click(screen.getByRole('tab', { name: /registracija/i }));
    await user.type(field(/email adresa/i), email);
    await user.type(field(/^master lozinka$/i), PASSWORD);
    await user.type(field(/ponovite/i), PASSWORD);
    await user.click(screen.getByRole('checkbox'));
    await user.click(button(/napravi nalog/i));
    await screen.findByRole('heading', { name: /sačuvajte kodove za oporavak/i });
  }

  const shownCodes = () =>
    screen
      .getAllByRole('listitem')
      .map((item) => item.textContent ?? '')
      .filter((text) => CODE_SHAPE.test(text));

  async function unlock(user: ReturnType<typeof userEvent.setup>) {
    await user.type(field(/^master lozinka$/i), PASSWORD);
    await user.click(button(/^otključaj$/i));
    await screen.findByRole('heading', { name: /vaš vault/i });
  }

  describe('posle registracije', () => {
    it('kodovi se prikazuju pre potvrde emaila, nastavak trazi potvrdu, a posle nastavka kodova nema', async () => {
      const { user, store } = await open();
      await register(user);

      const list = shownCodes();
      expect(list).toHaveLength(3);
      expect(new Set(list).size).toBe(3);
      expect(screen.getByText(/dobili ste 3 kodova za oporavak/i)).toBeInTheDocument();
      expect(screen.getByText(/svaki kod važi samo jednom/i)).toBeInTheDocument();

      expect(button(/^nastavi$/i)).toBeDisabled();
      await user.click(screen.getByRole('checkbox', { name: /sačuvao/i }));
      expect(button(/^nastavi$/i)).toBeEnabled();
      await user.click(button(/^nastavi$/i));

      expect(await screen.findByRole('heading', { name: /potvrdite email/i })).toBeInTheDocument();
      for (const code of list) expect(document.body.textContent).not.toContain(code);
      expect(JSON.stringify(store.getState())).not.toContain(list[0] as string);
    });

    it('kopiranje svih kodova: klipbord se brise posle 30 sekundi', async () => {
      const { user, clipboard } = await open({ timers: true });
      await register(user);
      const list = shownCodes();

      await user.click(button(/kopiraj sve/i));
      expect(clipboard.text).toBe(list.join('\n'));
      expect(await screen.findByText(/briše za 30 sekundi/i)).toBeInTheDocument();

      await act(async () => {
        await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
      });
      expect(clipboard.text).toBe('');
    });

    it('odlazak sa ekrana odmah brise kopirane kodove', async () => {
      const { user, clipboard } = await open({ timers: true });
      await register(user);
      await user.click(button(/kopiraj sve/i));
      expect(clipboard.text).not.toBe('');

      await user.click(button(/^nazad$/i));
      expect(await screen.findByRole('tab', { name: /prijava/i })).toBeInTheDocument();
      expect(clipboard.text).toBe('');
    });

    it('preuzimanje pravi tekstualni fajl sa nalogom i svim kodovima', async () => {
      const { user } = await open();
      await register(user, 'nov@example.com');
      const list = shownCodes();

      const blobs: Blob[] = [];
      URL.createObjectURL = vi.fn((blob: Blob) => {
        blobs.push(blob);
        return 'blob:test';
      });
      URL.revokeObjectURL = vi.fn();
      let downloadName = '';
      vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
        this: HTMLAnchorElement,
      ) {
        downloadName = this.download;
      });

      await user.click(button(/preuzmi/i));
      expect(downloadName).toBe('sleepsafe-kodovi-za-oporavak.txt');
      expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:test');
      const text = await blobs[0]?.text();
      expect(text).toContain('Nalog: nov@example.com');
      for (const code of list) expect(text).toContain(code);
    });

    it('stampanje poziva stampanje stranice', async () => {
      const { user } = await open();
      await register(user);
      const print = vi.fn();
      window.print = print;
      await user.click(button(/štampaj/i));
      expect(print).toHaveBeenCalledTimes(1);
    });

    it('ako pregledac odbije kopiranje, korisnik dobija poruku', async () => {
      const { user, clipboard } = await open();
      await register(user);
      vi.spyOn(clipboard, 'writeText').mockRejectedValueOnce(new Error('denied'));
      await user.click(button(/kopiraj sve/i));
      expect(await screen.findByRole('alert')).toHaveTextContent(/kopiranje nije uspelo/i);
    });

    it('"Nazad" odbacuje kodove i vraca na prijavu', async () => {
      const { user, store } = await open();
      await register(user);
      await user.click(button(/^nazad$/i));
      expect(await screen.findByRole('tab', { name: /prijava/i })).toBeInTheDocument();
      expect(store.getState()).toEqual({ status: 'signedOut' });
    });
  });

  describe('zaboravljena master lozinka', () => {
    async function toRecoveryCodeStep(user: ReturnType<typeof userEvent.setup>) {
      await user.click(button(/zaboravili ste master lozinku/i));
      await user.type(field(/email adresa/i), EMAIL);
      await user.click(button(/pošalji kod/i));
      await user.type(await screen.findByLabelText(/kod iz emaila/i), CODE);
      await user.click(button(/^potvrdi$/i));
      await screen.findByRole('heading', { name: /unesite kod za oporavak/i });
    }

    it('cela tacka: email, kod iz emaila, kod za oporavak, nova lozinka, prijava novom lozinkom', async () => {
      const { user } = await open({ seeded: true });

      await user.click(button(/zaboravili ste master lozinku/i));
      expect(screen.getByRole('heading', { name: /oporavak naloga/i })).toBeInTheDocument();
      await user.type(field(/email adresa/i), EMAIL);
      await user.click(button(/pošalji kod/i));

      expect(
        await screen.findByRole('heading', { name: /unesite kod iz emaila/i }),
      ).toBeInTheDocument();
      expect(screen.getByText(new RegExp(`nalog ${EMAIL} postoji`, 'i'))).toBeInTheDocument();
      await user.type(field(/kod iz emaila/i), '000000');
      await user.click(button(/^potvrdi$/i));
      expect(await screen.findByRole('alert')).toHaveTextContent(/nije ispravan ili je istekao/i);
      await user.clear(field(/kod iz emaila/i));
      await user.type(field(/kod iz emaila/i), CODE);
      await user.click(button(/^potvrdi$/i));

      expect(
        await screen.findByRole('heading', { name: /unesite kod za oporavak/i }),
      ).toBeInTheDocument();
      await user.type(field(/kod za oporavak/i), 'aaaaa-bbbbb');
      await user.click(button(/proveri kod/i));
      expect(await screen.findByRole('alert')).toHaveTextContent(/ne otvara vault/i);
      await user.clear(field(/kod za oporavak/i));
      await user.type(field(/kod za oporavak/i), (codes[1] as string).toLowerCase());
      expect(field(/kod za oporavak/i)).toHaveValue(codes[1]);
      await user.click(button(/proveri kod/i));

      expect(
        await screen.findByRole('heading', { name: /nova master lozinka/i }),
      ).toBeInTheDocument();
      await user.type(field(/^master lozinka$/i), 'kratka');
      await user.type(field(/ponovite/i), 'kratka');
      await user.click(button(/postavi lozinku/i));
      expect(screen.getByRole('alert')).toHaveTextContent(/najmanje 12 znakova/i);

      await user.clear(field(/^master lozinka$/i));
      await user.clear(field(/ponovite/i));
      await user.type(field(/^master lozinka$/i), NEW_PASSWORD);
      await user.type(field(/ponovite/i), NEW_PASSWORD + 'x');
      await user.click(button(/postavi lozinku/i));
      expect(screen.getByRole('alert')).toHaveTextContent(/ne poklapaju/i);

      await user.clear(field(/ponovite/i));
      await user.type(field(/ponovite/i), NEW_PASSWORD);
      await user.click(button(/postavi lozinku/i));
      expect(screen.getByRole('alert')).toHaveTextContent(/ne može povratiti/i);

      await user.click(screen.getByRole('checkbox'));
      await user.click(button(/postavi lozinku/i));
      expect(await screen.findByRole('status')).toHaveTextContent(/master lozinka je promenjena/i);

      // Prijava novom lozinkom (i kodom iz emaila) vodi u vault.
      await user.type(field(/email adresa/i), EMAIL);
      await user.type(field(/^master lozinka$/i), NEW_PASSWORD);
      await user.click(button(/^prijavi se$/i));
      await user.type(await screen.findByLabelText(/kod iz emaila/i), CODE);
      await user.click(button(/^potvrdi$/i));
      expect(await screen.findByRole('heading', { name: /vaš vault/i })).toBeInTheDocument();
    });

    it('neispravan oblik koda daje poruku o obliku, a ne o pogresnom kodu', async () => {
      const { user } = await open({ seeded: true });
      await toRecoveryCodeStep(user);
      await user.type(field(/kod za oporavak/i), 'abc');
      await user.click(button(/proveri kod/i));
      expect(await screen.findByRole('alert')).toHaveTextContent(/nije u ispravnom obliku/i);
    });

    it('nepostojeci nalog: ista poruka i isti tok kao za postojeci, odbija se tek kod koda iz emaila', async () => {
      const { user } = await open();
      await user.click(button(/zaboravili ste master lozinku/i));
      await user.type(field(/email adresa/i), 'nepoznat@example.com');
      await user.click(button(/pošalji kod/i));
      expect(
        await screen.findByRole('heading', { name: /unesite kod iz emaila/i }),
      ).toBeInTheDocument();
      await user.type(field(/kod iz emaila/i), CODE);
      await user.click(button(/^potvrdi$/i));
      expect(await screen.findByRole('alert')).toHaveTextContent(/nije ispravan ili je istekao/i);
    });

    it('"Nazad na prijavu" i "Nazad" vracaju na prijavu bez ostataka', async () => {
      const { user, store } = await open({ seeded: true });
      await user.click(button(/zaboravili ste master lozinku/i));
      await user.click(button(/nazad na prijavu/i));
      expect(screen.getByRole('tab', { name: /prijava/i })).toBeInTheDocument();

      await toRecoveryCodeStep(user);
      await user.click(button(/^nazad$/i));
      expect(await screen.findByRole('tab', { name: /prijava/i })).toBeInTheDocument();
      expect(store.getState()).toEqual({ status: 'signedOut' });
    });
  });

  describe('upravljanje kodovima u vaultu', () => {
    async function openVault() {
      const opened = await open({ seeded: true });
      opened.server.startSession(EMAIL);
      await opened.store.boot();
      await unlock(opened.user);
      await opened.user.click(button(/^kodovi za oporavak$/i));
      await screen.findByRole('heading', { name: /^kodovi za oporavak$/i });
      return opened;
    }

    it('prikazuje koliko je kodova ostalo, uz upozorenje kad ih je malo', async () => {
      await openVault();
      expect(
        await screen.findByText(/preostalo neiskorišćenih kodova: 3 od 3/i),
      ).toBeInTheDocument();
      expect(screen.getByText(/ostalo je malo kodova/i)).toBeInTheDocument();
    });

    it('novi kodovi traze lozinku: pogresna se odbija, prava pravi novi skup i prikazuje ga', async () => {
      const { user, server } = await openVault();
      await user.type(field(/^master lozinka$/i), 'pogresna lozinka');
      await user.click(button(/napravi nove kodove/i));
      expect(await screen.findByRole('alert')).toHaveTextContent(/pogrešna master lozinka/i);
      expect(server.callsTo('replaceRecoveryCodes')).toHaveLength(0);

      await user.clear(field(/^master lozinka$/i));
      await user.type(field(/^master lozinka$/i), PASSWORD);
      await user.click(button(/napravi nove kodove/i));

      expect(
        await screen.findByRole('heading', { name: /sačuvajte kodove za oporavak/i }),
      ).toBeInTheDocument();
      const fresh = shownCodes();
      expect(fresh).toHaveLength(3);
      expect(fresh.some((code) => codes.includes(code))).toBe(false);

      await user.click(button(/^gotovo$/i));
      expect(await screen.findByText(/vault je prazan/i)).toBeInTheDocument();
      for (const code of fresh) expect(document.body.textContent).not.toContain(code);
    });

    it('"Nazad" vraca na listu stavki', async () => {
      const { user } = await openVault();
      await user.click(button(/^nazad$/i));
      expect(await screen.findByText(/vault je prazan/i)).toBeInTheDocument();
    });
  });
});
