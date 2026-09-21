import { useEffect, useState } from 'react';
import { t } from '../strings';
import { CLIPBOARD_CLEAR_MS, ClipboardGuard } from '../vault/clipboard';

interface RecoveryCodesListProps {
  codes: readonly string[];
  email?: string;
}

function fileContent(codes: readonly string[], email: string | undefined): string {
  return [
    t.recoveryCodes.fileHeader,
    ...(email ? [t.recoveryCodes.fileAccount(email)] : []),
    new Date().toISOString(),
    '',
    t.recoveryCodes.fileNote,
    '',
    ...codes.map((code, index) => `${String(index + 1).padStart(2, ' ')}. ${code}`),
    '',
  ].join('\n');
}

// Lista kodova sa kopiranjem (klipbord se brise), preuzimanjem i stampom. Kodovi zive samo u
// pozivaocu: ovde se nista ne cuva.
export function RecoveryCodesList({ codes, email }: RecoveryCodesListProps) {
  const [guard] = useState(() => new ClipboardGuard());
  const [feedback, setFeedback] = useState<{ kind: 'info' | 'error'; text: string } | null>(null);

  // Odlazak sa ekrana brise ono sto je kopirano.
  useEffect(
    () => () => {
      void guard.flush();
    },
    [guard],
  );

  const copyAll = async () => {
    try {
      await guard.copy(codes.join('\n'), true);
      setFeedback({ kind: 'info', text: t.recoveryCodes.copied(CLIPBOARD_CLEAR_MS / 1000) });
    } catch {
      setFeedback({ kind: 'error', text: t.recoveryCodes.copyFailed });
    }
  };

  const download = () => {
    const blob = new Blob([fileContent(codes, email)], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = t.recoveryCodes.fileName;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="stack">
      <div className="print-area">
        <p className="print-only">{t.recoveryCodes.fileHeader}</p>
        {email ? <p className="print-only">{t.recoveryCodes.fileAccount(email)}</p> : null}
        <ol className="codes" aria-label={t.recoveryCodes.listLabel}>
          {codes.map((code) => (
            <li key={code}>
              <code>{code}</code>
            </li>
          ))}
        </ol>
      </div>
      <div className="row">
        <button type="button" className="secondary small" onClick={() => void copyAll()}>
          {t.recoveryCodes.copyAll}
        </button>
        <button type="button" className="secondary small" onClick={download}>
          {t.recoveryCodes.download}
        </button>
        <button type="button" className="secondary small" onClick={() => window.print()}>
          {t.recoveryCodes.print}
        </button>
      </div>
      {feedback && (
        <p
          role={feedback.kind === 'error' ? 'alert' : 'status'}
          className={`message ${feedback.kind}`}
        >
          {feedback.text}
        </p>
      )}
    </div>
  );
}
