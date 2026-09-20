import { type FormEvent, useState } from 'react';
import { ErrorMessage, TextField } from '../components/Fields';
import { useAction } from '../hooks';
import { t } from '../strings';

interface CodeScreenProps {
  title: string;
  intro: string;
  onSubmit: (code: string) => Promise<void>;
  onResend: () => Promise<void>;
  onBack: () => void;
}

export function CodeScreen({ title, intro, onSubmit, onResend, onBack }: CodeScreenProps) {
  const { busy, error, setError, run } = useAction();
  const [code, setCode] = useState('');
  const [resent, setResent] = useState(false);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!/^\d{6}$/.test(code.trim())) {
      setError(t.errors.codeFormat);
      return;
    }
    setResent(false);
    void run(() => onSubmit(code));
  };

  const resend = () => {
    setResent(false);
    void run(async () => {
      await onResend();
      setResent(true);
    });
  };

  return (
    <form onSubmit={submit} className="stack" noValidate>
      <h2>{title}</h2>
      <p className="hint">{intro}</p>
      <TextField
        label={t.fields.code}
        value={code}
        onChange={(value) => setCode(value.replace(/\D/g, '').slice(0, 6))}
        autoComplete="one-time-code"
        disabled={busy}
        autoFocus
      />
      <ErrorMessage message={error} />
      {resent ? (
        <p role="status" className="message info">
          {t.code.resent}
        </p>
      ) : null}
      <button type="submit" disabled={busy || code.length !== 6}>
        {t.code.submit}
      </button>
      <div className="row">
        <button type="button" className="secondary" disabled={busy} onClick={resend}>
          {t.code.resend}
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={onBack}>
          {t.code.back}
        </button>
      </div>
    </form>
  );
}
