import { type ReactNode, useState } from 'react';
import { ErrorMessage } from '../components/Fields';
import { useAction } from '../hooks';
import { t } from '../strings';
import { CLIPBOARD_CLEAR_MS, type ClipboardGuard } from '../vault/clipboard';
import type { VaultEntry, VaultStore } from '../vault/store';
import { toSafeUrl } from '../vault/url';

interface ItemViewProps {
  vault: VaultStore;
  entry: VaultEntry;
  guard: ClipboardGuard;
  onBack: () => void;
  onEdit: () => void;
}

type Feedback = { kind: 'info' | 'error'; text: string } | null;

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="detail">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function formatDate(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString('sr-Latn');
}

export function ItemView({ vault, entry, guard, onBack, onEdit }: ItemViewProps) {
  const { busy, error, run } = useAction();
  const [revealed, setRevealed] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const { data } = entry;
  const link = toSafeUrl(data.url);
  const looksLikeScheme = /^[a-z][a-z0-9+.-]*:/i.test(data.url.trim());

  const copy = async (text: string, sensitive: boolean, message: string) => {
    try {
      await guard.copy(text, sensitive);
      setFeedback({ kind: 'info', text: message });
    } catch {
      setFeedback({ kind: 'error', text: t.item.copyFailed });
    }
  };

  return (
    <div className="stack">
      <h2>{data.title}</h2>
      <dl className="details">
        <Detail label={t.item.username}>
          {data.username === '' ? (
            <span className="hint">{t.item.empty}</span>
          ) : (
            <span className="value">
              <span>{data.username}</span>
              <button
                type="button"
                className="secondary small"
                aria-label={t.item.copyUsernameLabel}
                onClick={() => void copy(data.username, false, t.item.copiedUsername)}
              >
                {t.item.copy}
              </button>
            </span>
          )}
        </Detail>
        <Detail label={t.item.password}>
          {data.password === '' ? (
            <span className="hint">{t.item.empty}</span>
          ) : (
            <span className="value">
              {revealed ? (
                <span className="mono">{data.password}</span>
              ) : (
                <>
                  <span aria-hidden="true">{'•'.repeat(10)}</span>
                  <span className="visually-hidden">{t.item.hidden}</span>
                </>
              )}
              <button
                type="button"
                className="secondary small"
                aria-pressed={revealed}
                onClick={() => setRevealed((shown) => !shown)}
              >
                {revealed ? t.item.conceal : t.item.reveal}
              </button>
              <button
                type="button"
                className="secondary small"
                aria-label={t.item.copyPasswordLabel}
                onClick={() =>
                  void copy(data.password, true, t.item.copiedPassword(CLIPBOARD_CLEAR_MS / 1000))
                }
              >
                {t.item.copy}
              </button>
            </span>
          )}
        </Detail>
        <Detail label={t.item.url}>
          {data.url === '' ? (
            <span className="hint">{t.item.empty}</span>
          ) : link ? (
            <a href={link} target="_blank" rel="noopener noreferrer">
              {data.url}
            </a>
          ) : (
            <>
              <span>{data.url}</span>
              {looksLikeScheme && <p className="hint">{t.item.unsafeUrl}</p>}
            </>
          )}
        </Detail>
        <Detail label={t.item.notes}>
          {data.notes === '' ? (
            <span className="hint">{t.item.empty}</span>
          ) : (
            <span className="notes">{data.notes}</span>
          )}
        </Detail>
      </dl>
      <p className="hint">{t.item.updated(formatDate(entry.updatedAt))}</p>

      {feedback && (
        <p
          role={feedback.kind === 'error' ? 'alert' : 'status'}
          className={`message ${feedback.kind}`}
        >
          {feedback.text}
        </p>
      )}
      <ErrorMessage message={error} />

      {confirming ? (
        <div className="stack">
          <p role="alert" className="message error">
            {t.item.confirmDelete(data.title)}
          </p>
          <div className="row">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => setConfirming(false)}
            >
              {t.item.confirmNo}
            </button>
            <button
              type="button"
              className="danger"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await vault.remove(entry.id);
                  onBack();
                })
              }
            >
              {t.item.confirmYes}
            </button>
          </div>
        </div>
      ) : (
        <div className="row">
          <button type="button" className="secondary" onClick={onBack}>
            {t.item.back}
          </button>
          <button type="button" className="secondary" onClick={onEdit}>
            {t.item.edit}
          </button>
          <button type="button" className="secondary" onClick={() => setConfirming(true)}>
            {t.item.delete}
          </button>
        </div>
      )}
    </div>
  );
}
