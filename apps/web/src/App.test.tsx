import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { App } from './App';
import { AuthProvider } from './auth/context';
import { AuthStore } from './auth/store';
import { inlineDeriver } from './crypto/deriver';
import { CODE, FakeServer, TEST_KDF } from './test/fakeServer';

const EMAIL = 'korisnik@example.com';
const PASSWORD = 'moja dugacka master lozinka';

async function setup(prepare?: (server: FakeServer) => Promise<void>) {
  const server = new FakeServer();
  await prepare?.(server);
  const store = new AuthStore({
    api: server,
    vaultApi: server,
    deriver: inlineDeriver,
    kdfParams: TEST_KDF,
  });
  await store.boot();
  const user = userEvent.setup();
  render(
    <AuthProvider store={store}>
      <App />
    </AuthProvider>,
  );
  return { server, store, user };
}

const sent = (server: FakeServer) => server.calls.filter((call) => call.name !== 'refresh');
const field = (name: RegExp) => screen.getByLabelText(name);
const button = (name: RegExp) => screen.getByRole('button', { name });

describe('App', () => {
  it('bez sesije prikazuje prijavu', async () => {
    await setup();
    expect(field(/email adresa/i)).toBeInTheDocument();
    expect(field(/^master lozinka$/i)).toBeInTheDocument();
    expect(button(/^prijavi se$/i)).toBeDisabled();
  });

  it('pokretanje sa vazecom sesijom trazi samo master lozinku', async () => {
    await setup(async (server) => {
      await server.seedUser(EMAIL, PASSWORD);
      server.startSession(EMAIL);
    });
    expect(screen.getByRole('heading', { name: /otključajte vault/i })).toBeInTheDocument();
    expect(screen.getByText(new RegExp(EMAIL))).toBeInTheDocument();
  });

  it('server nedostupan pri pokretanju: poruka na ekranu prijave', async () => {
    await setup(async (server) => {
      server.down = true;
    });
    expect(screen.getByRole('status')).toHaveTextContent(/server trenutno nije dostupan/i);
  });

  describe('registracija', () => {
    async function openRegister(user: ReturnType<typeof userEvent.setup>) {
      await user.click(screen.getByRole('tab', { name: /registracija/i }));
    }

    it('proverava duzinu lozinke, poklapanje i potvrdu da se lozinka ne moze povratiti', async () => {
      const { user, server } = await setup();
      await openRegister(user);

      await user.type(field(/email adresa/i), EMAIL);
      await user.type(field(/^master lozinka$/i), 'kratka');
      await user.type(field(/ponovite/i), 'kratka');
      await user.click(button(/napravi nalog/i));
      expect(screen.getByRole('alert')).toHaveTextContent(/najmanje 12 znakova/i);

      await user.clear(field(/^master lozinka$/i));
      await user.clear(field(/ponovite/i));
      await user.type(field(/^master lozinka$/i), PASSWORD);
      await user.type(field(/ponovite/i), PASSWORD + 'x');
      await user.click(button(/napravi nalog/i));
      expect(screen.getByRole('alert')).toHaveTextContent(/ne poklapaju/i);

      await user.clear(field(/ponovite/i));
      await user.type(field(/ponovite/i), PASSWORD);
      await user.click(button(/napravi nalog/i));
      expect(screen.getByRole('alert')).toHaveTextContent(/ne može povratiti/i);

      expect(sent(server)).toHaveLength(0);
    });

    it('neispravan email daje poruku, bez zahteva ka serveru', async () => {
      const { user, server } = await setup();
      await openRegister(user);
      await user.type(field(/email adresa/i), 'nije-email');
      await user.type(field(/^master lozinka$/i), PASSWORD);
      await user.type(field(/ponovite/i), PASSWORD);
      await user.click(screen.getByRole('checkbox'));
      await user.click(button(/napravi nalog/i));

      expect(await screen.findByRole('alert')).toHaveTextContent(/ispravnu email adresu/i);
      expect(sent(server)).toHaveLength(0);
    });

    it('dugme "Prikazi" otkriva lozinku i ponovo je sakriva', async () => {
      const { user } = await setup();
      const input = field(/^master lozinka$/i);
      expect(input).toHaveAttribute('type', 'password');
      await user.click(screen.getAllByRole('button', { name: /prikaži/i })[0] as HTMLElement);
      expect(input).toHaveAttribute('type', 'text');
      await user.click(screen.getAllByRole('button', { name: /sakrij/i })[0] as HTMLElement);
      expect(input).toHaveAttribute('type', 'password');
    });
  });

  it('cela tacka kroz interfejs: registracija, potvrda emaila, prijava, kod, zakljucavanje', async () => {
    const { user, server } = await setup();

    await user.click(screen.getByRole('tab', { name: /registracija/i }));
    await user.type(field(/email adresa/i), EMAIL);
    await user.type(field(/^master lozinka$/i), PASSWORD);
    await user.type(field(/ponovite/i), PASSWORD);
    await user.click(screen.getByRole('checkbox'));
    await user.click(button(/napravi nalog/i));

    expect(await screen.findByRole('heading', { name: /potvrdite email/i })).toBeInTheDocument();
    await user.type(field(/kod iz emaila/i), '000000');
    await user.click(button(/^potvrdi$/i));
    expect(await screen.findByRole('alert')).toHaveTextContent(/nije ispravan ili je istekao/i);
    await user.clear(field(/kod iz emaila/i));
    await user.type(field(/kod iz emaila/i), CODE);
    await user.click(button(/^potvrdi$/i));

    expect(await screen.findByRole('status')).toHaveTextContent(/email je potvrđen/i);
    await user.type(field(/email adresa/i), EMAIL);
    await user.type(field(/^master lozinka$/i), PASSWORD);
    await user.click(button(/^prijavi se$/i));

    expect(
      await screen.findByRole('heading', { name: /unesite kod za prijavu/i }),
    ).toBeInTheDocument();
    await user.type(field(/kod iz emaila/i), CODE);
    await user.click(button(/^potvrdi$/i));

    expect(await screen.findByRole('heading', { name: /vault je otključan/i })).toBeInTheDocument();
    expect(screen.getByText(new RegExp(EMAIL))).toBeInTheDocument();

    await user.click(button(/^zaključaj$/i));
    expect(screen.getByRole('heading', { name: /otključajte vault/i })).toBeInTheDocument();
    await user.type(field(/^master lozinka$/i), 'pogresna master lozinka');
    await user.click(button(/^otključaj$/i));
    expect(await screen.findByRole('alert')).toHaveTextContent(/pogrešna master lozinka/i);
    await user.clear(field(/^master lozinka$/i));
    await user.type(field(/^master lozinka$/i), PASSWORD);
    await user.click(button(/^otključaj$/i));
    expect(await screen.findByRole('heading', { name: /vault je otključan/i })).toBeInTheDocument();

    await user.click(button(/^odjavi se$/i));
    expect(await screen.findByRole('tab', { name: /prijava/i })).toBeInTheDocument();
    expect(server.callsTo('logout')).toHaveLength(1);
    expect(JSON.stringify(server.calls)).not.toContain(PASSWORD);
  });

  it('pogresna lozinka pri prijavi: opsta poruka, bez prelaska na kod', async () => {
    const { user } = await setup(async (server) => {
      await server.seedUser(EMAIL, PASSWORD);
    });
    await user.type(field(/email adresa/i), EMAIL);
    await user.type(field(/^master lozinka$/i), 'pogresna master lozinka');
    await user.click(button(/^prijavi se$/i));

    expect(await screen.findByRole('alert')).toHaveTextContent(/pogrešan email ili lozinka/i);
    expect(screen.queryByRole('heading', { name: /kod/i })).not.toBeInTheDocument();
  });

  it('odustajanje od koda za prijavu vraca na prijavu', async () => {
    const { user } = await setup(async (server) => {
      await server.seedUser(EMAIL, PASSWORD);
    });
    await user.type(field(/email adresa/i), EMAIL);
    await user.type(field(/^master lozinka$/i), PASSWORD);
    await user.click(button(/^prijavi se$/i));
    await screen.findByRole('heading', { name: /unesite kod za prijavu/i });

    await user.click(button(/^nazad$/i));
    expect(await screen.findByRole('tab', { name: /prijava/i })).toBeInTheDocument();
  });

  it('kod prima samo cifre i najvise 6 znakova', async () => {
    const { user } = await setup(async (server) => {
      await server.seedUser(EMAIL, PASSWORD);
    });
    await user.type(field(/email adresa/i), EMAIL);
    await user.type(field(/^master lozinka$/i), PASSWORD);
    await user.click(button(/^prijavi se$/i));
    await screen.findByRole('heading', { name: /unesite kod za prijavu/i });

    await user.type(field(/kod iz emaila/i), 'a1b2c3d4e5f6g7');
    expect(field(/kod iz emaila/i)).toHaveValue('123456');
  });
});
