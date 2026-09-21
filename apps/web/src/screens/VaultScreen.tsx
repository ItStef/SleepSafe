import { useEffect, useMemo, useState } from 'react';
import { useAuthStore } from '../auth/context';
import type { SessionUser } from '../auth/store';
import { TextField } from '../components/Fields';
import { describeError } from '../errors';
import { t } from '../strings';
import { ClipboardGuard } from '../vault/clipboard';
import { useIdleLock, useVaultState, useVaultSync } from '../vault/hooks';
import { filterEntries } from '../vault/search';
import type { VaultStore } from '../vault/store';
import { ItemForm } from './ItemForm';
import { ItemView } from './ItemView';
import { RecoveryManageScreen } from './RecoveryScreens';

type View =
  | { kind: 'list' }
  | { kind: 'recovery' }
  | { kind: 'view'; id: string }
  | { kind: 'form'; id: string | null };

export function VaultScreen({ user, vault }: { user: SessionUser; vault: VaultStore }) {
  const auth = useAuthStore();
  const state = useVaultState(vault);
  const [view, setView] = useState<View>({ kind: 'list' });
  const [query, setQuery] = useState('');
  const [guard] = useState(() => new ClipboardGuard());

  useVaultSync(vault);
  useIdleLock(() => auth.lock());
  // Zakljucavanje (ili odjava) ugasi ovaj ekran: tajna iz klipborda se brise odmah.
  useEffect(
    () => () => {
      void guard.flush();
    },
    [guard],
  );

  const visible = useMemo(() => filterEntries(state.entries, query), [state.entries, query]);
  const viewedId = view.kind === 'view' || view.kind === 'form' ? view.id : null;
  const selected =
    viewedId === null ? undefined : state.entries.find((entry) => entry.id === viewedId);
  // Stavka koju gledamo je mozda obrisana na drugom uredjaju: tada se vracamo na listu.
  const current: View = viewedId !== null && !selected ? { kind: 'list' } : view;

  const header = (
    <div className="toolbar">
      <div>
        <h2>{t.vault.title}</h2>
        <p className="hint">{t.vault.signedInAs(user.email)}</p>
      </div>
      <div className="row">
        <button
          type="button"
          className="secondary small"
          onClick={() => setView({ kind: 'recovery' })}
        >
          {t.recoveryManage.open}
        </button>
        <button type="button" className="secondary small" onClick={() => auth.lock()}>
          {t.vault.lock}
        </button>
        <button type="button" className="secondary small" onClick={() => void auth.logout()}>
          {t.vault.logout}
        </button>
      </div>
    </div>
  );

  if (current.kind === 'recovery') {
    return (
      <div className="stack">
        {header}
        <RecoveryManageScreen onBack={() => setView({ kind: 'list' })} />
      </div>
    );
  }

  if (current.kind === 'form') {
    return (
      <div className="stack">
        {header}
        <ItemForm
          key={current.id ?? 'new'}
          vault={vault}
          {...(selected ? { entry: selected } : {})}
          onDone={(id) => setView({ kind: 'view', id })}
          onCancel={() => setView(selected ? { kind: 'view', id: selected.id } : { kind: 'list' })}
        />
      </div>
    );
  }

  if (current.kind === 'view' && selected) {
    return (
      <div className="stack">
        {header}
        <ItemView
          key={selected.id}
          vault={vault}
          entry={selected}
          guard={guard}
          onBack={() => setView({ kind: 'list' })}
          onEdit={() => setView({ kind: 'form', id: selected.id })}
        />
      </div>
    );
  }

  const loading = state.status === 'loading' || state.status === 'idle';
  return (
    <div className="stack">
      {header}
      <div className="toolbar">
        <div className="grow">
          <TextField
            label={t.vault.search}
            type="search"
            value={query}
            onChange={setQuery}
            autoComplete="off"
          />
        </div>
        <button type="button" onClick={() => setView({ kind: 'form', id: null })}>
          {t.vault.add}
        </button>
      </div>

      {state.status === 'error' && (
        <div className="stack">
          <p role="alert" className="message error">
            {t.vault.loadFailed} {describeError(state.error)}
          </p>
          <button type="button" className="secondary" onClick={() => void vault.sync()}>
            {t.vault.retry}
          </button>
        </div>
      )}
      {state.status === 'ready' && state.error !== null && (
        <p role="status" className="message info">
          {t.vault.syncFailed}{' '}
          <button type="button" className="link" onClick={() => void vault.sync()}>
            {t.vault.retry}
          </button>
        </p>
      )}
      {state.unreadable > 0 && (
        <p role="status" className="message error">
          {t.vault.unreadable(state.unreadable)}
        </p>
      )}
      {loading && state.entries.length === 0 && (
        <p role="status" className="hint">
          {t.vault.loading}
        </p>
      )}
      {state.status === 'ready' && state.entries.length === 0 && (
        <p className="hint">{t.vault.empty}</p>
      )}
      {state.entries.length > 0 && visible.length === 0 && (
        <p className="hint">{t.vault.noResults}</p>
      )}
      {visible.length > 0 && (
        <>
          <p className="hint">{t.vault.count(visible.length, state.entries.length)}</p>
          <ul className="entries">
            {visible.map((entry) => (
              <li key={entry.id}>
                <button
                  type="button"
                  className="entry"
                  onClick={() => setView({ kind: 'view', id: entry.id })}
                >
                  <span className="entry-title">{entry.data.title}</span>
                  <span className="entry-sub">
                    {entry.data.username || entry.data.url || t.vault.untitledHint}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
