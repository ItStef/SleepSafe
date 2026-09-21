import { type FormEvent, useState } from 'react';
import { ErrorMessage, PasswordField, TextField } from '../components/Fields';
import { useAuthStore } from '../auth/context';
import { MIN_MASTER_PASSWORD_LENGTH } from '../auth/policy';
import type { Notice } from '../auth/store';
import { useAction } from '../hooks';
import { t } from '../strings';

function LoginForm() {
  const store = useAuthStore();
  const { busy, error, run } = useAction();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void run(() => store.login(email, password));
  };

  return (
    <form onSubmit={submit} className="stack">
      <TextField
        label={t.fields.email}
        type="email"
        value={email}
        onChange={setEmail}
        autoComplete="username"
        disabled={busy}
        autoFocus
      />
      <PasswordField
        label={t.fields.password}
        value={password}
        onChange={setPassword}
        autoComplete="current-password"
        disabled={busy}
      />
      <ErrorMessage message={error} />
      <button type="submit" disabled={busy || email === '' || password === ''}>
        {busy ? t.login.working : t.login.submit}
      </button>
    </form>
  );
}

function RegisterForm() {
  const store = useAuthStore();
  const { busy, error, run } = useAction();
  const [email, setEmail] = useState('');
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
    void run(() => store.register(email, password));
  };

  return (
    <form onSubmit={submit} className="stack" noValidate>
      <p className="hint">{t.register.intro}</p>
      <TextField
        label={t.fields.email}
        type="email"
        value={email}
        onChange={setEmail}
        autoComplete="username"
        disabled={busy}
        autoFocus
      />
      <PasswordField
        label={t.fields.password}
        value={password}
        onChange={setPassword}
        autoComplete="new-password"
        disabled={busy}
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
      <button type="submit" disabled={busy || email === ''}>
        {busy ? t.register.working : t.register.submit}
      </button>
    </form>
  );
}

export function SignedOutScreen({ notice }: { notice: Notice | undefined }) {
  const [tab, setTab] = useState<'login' | 'register'>('login');
  return (
    <div className="stack">
      {notice ? (
        <p role="status" className="message info">
          {t.notices[notice]}
        </p>
      ) : null}
      <div className="tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'login'}
          onClick={() => setTab('login')}
        >
          {t.tabs.login}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'register'}
          onClick={() => setTab('register')}
        >
          {t.tabs.register}
        </button>
      </div>
      {tab === 'login' ? <LoginForm /> : <RegisterForm />}
    </div>
  );
}
