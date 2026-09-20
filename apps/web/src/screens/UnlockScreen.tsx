import { type FormEvent, useState } from 'react';
import { ErrorMessage, PasswordField } from '../components/Fields';
import { useAuthStore } from '../auth/context';
import { useAction } from '../hooks';
import { t } from '../strings';

export function UnlockScreen({ email }: { email: string }) {
  const store = useAuthStore();
  const { busy, error, run } = useAction();
  const [password, setPassword] = useState('');

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void run(() => store.unlock(password));
  };

  return (
    <form onSubmit={submit} className="stack">
      <h2>{t.unlock.title}</h2>
      <p className="hint">{t.unlock.intro(email)}</p>
      {/* Skriveno polje sa email adresom pomaze menadzerima lozinki da prepoznaju nalog. */}
      <input type="text" name="username" value={email} autoComplete="username" readOnly hidden />
      <PasswordField
        label={t.fields.password}
        value={password}
        onChange={setPassword}
        autoComplete="current-password"
        disabled={busy}
        autoFocus
      />
      <ErrorMessage message={error} />
      <button type="submit" disabled={busy || password === ''}>
        {busy ? t.unlock.working : t.unlock.submit}
      </button>
      <button
        type="button"
        className="secondary"
        disabled={busy}
        onClick={() => void store.logout()}
      >
        {t.unlock.logout}
      </button>
    </form>
  );
}
