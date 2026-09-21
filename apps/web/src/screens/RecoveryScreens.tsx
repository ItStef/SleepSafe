import { type FormEvent, useEffect, useState } from 'react';
import { useAuthStore } from '../auth/context';
import { MIN_MASTER_PASSWORD_LENGTH } from '../auth/policy';
import { ErrorMessage, PasswordField, TextField } from '../components/Fields';
import { RecoveryCodesList } from '../components/RecoveryCodesList';
import { useAction } from '../hooks';
import { t } from '../strings';

// Posle registracije: kodovi se prikazuju jednom, a nalog se ne nastavlja dok korisnik ne
// potvrdi da ih je sacuvao.
export function RecoveryCodesScreen({ email, codes }: { email: string; codes: readonly string[] }) {
  const store = useAuthStore();
  const [acknowledged, setAcknowledged] = useState(false);
  return (
    <div className="stack">
      <h2>{t.recoveryCodes.title}</h2>
      <p className="hint">{t.recoveryCodes.intro(codes.length)}</p>
      <ul className="rules">
        {t.recoveryCodes.rules.map((rule) => (
          <li key={rule}>{rule}</li>
        ))}
      </ul>
      <RecoveryCodesList codes={codes} email={email} />
      <label className="checkbox">
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        <span>{t.recoveryCodes.acknowledge}</span>
      </label>
      <button
        type="button"
        disabled={!acknowledged}
        onClick={() => store.acknowledgeRecoveryCodes()}
      >
        {t.recoveryCodes.continue}
      </button>
      <button type="button" className="secondary" onClick={() => store.cancelPending()}>
        {t.recoveryCodes.back}
      </button>
    </div>
  );
}

// Forma na ekranu prijave: email naloga koji se oporavlja.
export function RecoveryStartForm({ onBack }: { onBack: () => void }) {
  const store = useAuthStore();
  const { busy, error, run } = useAction();
  const [email, setEmail] = useState('');

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void run(() => store.startRecovery(email));
  };

  return (
    <form onSubmit={submit} className="stack" noValidate>
      <h2>{t.recover.title}</h2>
      <p className="hint">{t.recover.intro}</p>
      <TextField
        label={t.fields.email}
        type="email"
        value={email}
        onChange={setEmail}
        autoComplete="username"
        disabled={busy}
        autoFocus
      />
      <ErrorMessage message={error} />
      <button type="submit" disabled={busy || email === ''}>
        {busy ? t.recover.working : t.recover.submit}
      </button>
      <button type="button" className="secondary" disabled={busy} onClick={onBack}>
        {t.recover.back}
      </button>
    </form>
  );
}

export function RecoveryCodeScreen() {
  const store = useAuthStore();
  const { busy, error, run } = useAction();
  const [code, setCode] = useState('');

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void run(() => store.submitRecoveryCode(code));
  };

  return (
    <form onSubmit={submit} className="stack" noValidate>
      <h2>{t.recover.codeTitle}</h2>
      <p className="hint">{t.recover.codeIntro}</p>
      <TextField
        label={t.recover.codeField}
        value={code}
        onChange={(value) => setCode(value.toUpperCase().slice(0, 12))}
        autoComplete="off"
        disabled={busy}
        autoFocus
      />
      <ErrorMessage message={error} />
      <button type="submit" disabled={busy || code.trim() === ''}>
        {busy ? t.recover.codeWorking : t.recover.codeSubmit}
      </button>
      <button
        type="button"
        className="secondary"
        disabled={busy}
        onClick={() => store.cancelPending()}
      >
        {t.recoveryCodes.back}
      </button>
    </form>
  );
}

export function RecoveryPasswordScreen() {
  const store = useAuthStore();
  const { busy, error, run } = useAction();
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (password.length < MIN_MASTER_PASSWORD_LENGTH) {
      setProblem(t.errors.passwordTooShort(MIN_MASTER_PASSWORD_LENGTH));
      return;
    }
    if (password !== confirm) {
      setProblem(t.errors.passwordMismatch);
      return;
    }
    if (!acknowledged) {
      setProblem(t.errors.acknowledgeRequired);
      return;
    }
    setProblem(null);
    void run(() => store.resetWithRecovery(password));
  };

  return (
    <form onSubmit={submit} className="stack" noValidate>
      <h2>{t.recover.passwordTitle}</h2>
      <p className="hint">{t.recover.passwordIntro}</p>
      <PasswordField
        label={t.fields.password}
        value={password}
        onChange={setPassword}
        autoComplete="new-password"
        disabled={busy}
        autoFocus
      />
      <PasswordField
        label={t.fields.confirm}
        value={confirm}
        onChange={setConfirm}
        autoComplete="new-password"
        disabled={busy}
      />
      <label className="checkbox">
        <input
          type="checkbox"
          checked={acknowledged}
          disabled={busy}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        <span>{t.register.acknowledge}</span>
      </label>
      <ErrorMessage message={problem ?? error} />
      <button type="submit" disabled={busy}>
        {busy ? t.recover.passwordWorking : t.recover.passwordSubmit}
      </button>
    </form>
  );
}

// U vaultu: koliko kodova je ostalo i pravljenje novog skupa.
export function RecoveryManageScreen({ onBack }: { onBack: () => void }) {
  const store = useAuthStore();
  const { busy, error, run } = useAction();
  const [status, setStatus] = useState<{
    total: number;
    remaining: number;
    createdAt: string | null;
  } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [fresh, setFresh] = useState<readonly string[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    store.recoveryStatus().then(
      (value) => {
        if (!cancelled) setStatus(value);
      },
      () => {
        if (!cancelled) setLoadError(t.errors.generic);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [store]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void run(async () => {
      const codes = await store.regenerateRecoveryCodes(password);
      setPassword('');
      setFresh(codes);
      setStatus({
        total: codes.length,
        remaining: codes.length,
        createdAt: new Date().toISOString(),
      });
    });
  };

  if (fresh) {
    return (
      <div className="stack">
        <h2>{t.recoveryCodes.title}</h2>
        <p className="hint">{t.recoveryCodes.intro(fresh.length)}</p>
        <ul className="rules">
          {t.recoveryCodes.rules.map((rule) => (
            <li key={rule}>{rule}</li>
          ))}
        </ul>
        <RecoveryCodesList codes={fresh} />
        <button
          type="button"
          onClick={() => {
            setFresh(null);
            onBack();
          }}
        >
          {t.recoveryManage.done}
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="stack" noValidate>
      <h2>{t.recoveryManage.title}</h2>
      {loadError ? <ErrorMessage message={loadError} /> : null}
      {status ? (
        <>
          <p role="status">
            {status.total === 0
              ? t.recoveryManage.none
              : t.recoveryManage.status(status.remaining, status.total)}
          </p>
          {status.total > 0 && status.remaining <= 3 ? (
            <p className="message info">{t.recoveryManage.low}</p>
          ) : null}
        </>
      ) : null}
      <h3>{t.recoveryManage.regenerateTitle}</h3>
      <p className="hint">{t.recoveryManage.regenerateHint}</p>
      <PasswordField
        label={t.fields.password}
        value={password}
        onChange={setPassword}
        autoComplete="current-password"
        disabled={busy}
      />
      <ErrorMessage message={error} />
      <button type="submit" disabled={busy || password === ''}>
        {busy ? t.recoveryManage.working : t.recoveryManage.submit}
      </button>
      <button type="button" className="secondary" disabled={busy} onClick={onBack}>
        {t.recoveryManage.back}
      </button>
    </form>
  );
}
