import type { SessionInfo } from '@sleepsafe/shared';
import { type FormEvent, useEffect, useRef, useState } from 'react';
import { describeUserAgent } from '../auth/agent';
import { useAuthStore } from '../auth/context';
import { MIN_MASTER_PASSWORD_LENGTH } from '../auth/policy';
import { downloadText } from '../components/download';
import { ErrorMessage, PasswordField } from '../components/Fields';
import { describeError } from '../errors';
import { useAction } from '../hooks';
import { t } from '../strings';
import {
  ImportError,
  type ImportOutcome,
  MAX_IMPORT_BYTES,
  type ParsedImport,
  exportCsv,
  exportJson,
  importItems,
  parseImport,
  withoutDuplicates,
} from '../vault/exchange';
import { useVaultState } from '../vault/hooks';
import type { VaultStore } from '../vault/store';

type Panel = 'sessions' | 'password' | 'transfer' | 'delete';

function formatDate(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString('sr-Latn');
}

function describeImportError(error: unknown): string {
  if (error instanceof ImportError) {
    switch (error.code) {
      case 'INVALID_FILE':
        return t.errors.importInvalid;
      case 'UNKNOWN_FORMAT':
        return t.errors.importUnknown;
      case 'EMPTY':
        return t.errors.importEmpty;
      case 'TOO_LARGE':
        return t.errors.importTooLarge;
      case 'TOO_MANY':
        return t.errors.importTooMany;
    }
  }
  return describeError(error);
}

function SessionsPanel() {
  const store = useAuthStore();
  const { busy, error, run } = useAction();
  const [sessions, setSessions] = useState<readonly SessionInfo[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let cancelled = false;
    store.listSessions().then(
      (response) => {
        if (!cancelled) {
          setSessions(response.sessions);
          setLoadError(null);
        }
      },
      (caught: unknown) => {
        if (!cancelled) setLoadError(describeError(caught));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [store, version]);

  const reload = () => setVersion((current) => current + 1);
  const others = (sessions ?? []).filter((session) => !session.current);

  return (
    <div className="stack">
      <h3>{t.account.sessions.title}</h3>
      <p className="hint">{t.account.sessions.hint}</p>
      {loadError ? <ErrorMessage message={loadError} /> : null}
      {sessions === null && loadError === null ? (
        <p role="status" className="hint">
          {t.account.sessions.loading}
        </p>
      ) : null}
      {sessions ? (
        <ul className="sessions">
          {sessions.map((session) => {
            const name = describeUserAgent(session.userAgent);
            return (
              <li key={session.id} className="session">
                <div>
                  <p className="session-name">
                    {name}
                    {session.current ? (
                      <span className="badge">{t.account.sessions.current}</span>
                    ) : null}
                  </p>
                  <p className="hint">
                    {t.account.sessions.created(formatDate(session.createdAt))}
                  </p>
                  <p className="hint">
                    {t.account.sessions.lastUsed(formatDate(session.lastUsedAt))}
                  </p>
                </div>
                {session.current ? null : (
                  <button
                    type="button"
                    className="secondary small"
                    aria-label={t.account.sessions.revokeLabel(name)}
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        await store.revokeSession(session.id);
                        reload();
                      })
                    }
                  >
                    {t.account.sessions.revoke}
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      ) : null}
      <ErrorMessage message={error} />
      {sessions && others.length === 0 ? (
        <p className="hint">{t.account.sessions.none}</p>
      ) : (
        <button
          type="button"
          className="secondary"
          disabled={busy || others.length === 0}
          onClick={() =>
            void run(async () => {
              await store.revokeOtherSessions();
              reload();
            })
          }
        >
          {t.account.sessions.revokeOthers}
        </button>
      )}
    </div>
  );
}

function ChangePasswordPanel() {
  const store = useAuthStore();
  const { busy, error, run } = useAction();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setDone(false);
    if (next.length < MIN_MASTER_PASSWORD_LENGTH) {
      setProblem(t.errors.passwordTooShort(MIN_MASTER_PASSWORD_LENGTH));
      return;
    }
    if (next !== confirm) {
      setProblem(t.errors.passwordMismatch);
      return;
    }
    if (!acknowledged) {
      setProblem(t.errors.acknowledgeRequired);
      return;
    }
    setProblem(null);
    void run(async () => {
      await store.changePassword(current, next);
      setCurrent('');
      setNext('');
      setConfirm('');
      setAcknowledged(false);
      setDone(true);
    });
  };

  return (
    <form onSubmit={submit} className="stack" noValidate>
      <h3>{t.account.password.title}</h3>
      <p className="hint">{t.account.password.intro}</p>
      <PasswordField
        label={t.account.password.current}
        value={current}
        onChange={setCurrent}
        autoComplete="current-password"
        disabled={busy}
      />
      <PasswordField
        label={t.account.password.next}
        value={next}
        onChange={setNext}
        autoComplete="new-password"
        disabled={busy}
      />
      <PasswordField
        label={t.account.password.confirm}
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
      {done ? (
        <p role="status" className="message info">
          {t.account.password.done}
        </p>
      ) : null}
      <button type="submit" disabled={busy || current === '' || next === ''}>
        {busy ? t.account.password.working : t.account.password.submit}
      </button>
    </form>
  );
}

function TransferPanel({ vault }: { vault: VaultStore }) {
  const store = useAuthStore();
  const state = useVaultState(vault);
  const exportAction = useAction();
  const importAction = useAction();
  const [password, setPassword] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [exported, setExported] = useState<number | null>(null);
  const [parsed, setParsed] = useState<ParsedImport | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [skipDuplicates, setSkipDuplicates] = useState(true);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [outcome, setOutcome] = useState<(ImportOutcome & { duplicates: number }) | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const doExport = (kind: 'json' | 'csv') =>
    void exportAction.run(async () => {
      await store.confirmPassword(password);
      const entries = vault.getState().entries;
      const day = new Date().toISOString().slice(0, 10);
      if (kind === 'json') {
        downloadText(`sleepsafe-izvoz-${day}.json`, exportJson(entries), 'application/json');
      } else {
        downloadText(`sleepsafe-izvoz-${day}.csv`, exportCsv(entries), 'text/csv');
      }
      setPassword('');
      setAcknowledged(false);
      setExported(entries.length);
    });

  const chooseFile = async (file: File | undefined) => {
    setParsed(null);
    setOutcome(null);
    setFileError(null);
    if (!file) return;
    try {
      if (file.size > MAX_IMPORT_BYTES) {
        throw new ImportError('TOO_LARGE');
      }
      setParsed(parseImport(await file.text(), file.name));
    } catch (caught) {
      setFileError(describeImportError(caught));
    }
  };

  const doImport = () => {
    if (!parsed) return;
    void importAction.run(async () => {
      const plan = skipDuplicates
        ? withoutDuplicates(parsed.items, vault.getState().entries)
        : { items: parsed.items, duplicates: 0 };
      setProgress({ done: 0, total: plan.items.length });
      try {
        const result = await importItems(vault, plan.items, (done, total) =>
          setProgress({ done, total }),
        );
        setOutcome({ ...result, duplicates: plan.duplicates });
      } finally {
        setProgress(null);
        void vault.sync();
      }
      setParsed(null);
      if (fileInput.current) fileInput.current.value = '';
    });
  };

  const stoppedText =
    outcome?.stopped === 'FULL'
      ? t.transfer.stoppedFull
      : outcome?.stopped === 'NETWORK'
        ? t.transfer.stoppedNetwork
        : outcome?.stopped === 'LOCKED'
          ? t.transfer.stoppedLocked
          : null;

  return (
    <div className="stack">
      <h3>{t.transfer.exportTitle}</h3>
      <p className="message error">{t.transfer.exportWarning}</p>
      {state.entries.length === 0 ? <p className="hint">{t.transfer.exportEmpty}</p> : null}
      <PasswordField
        label={t.transfer.password}
        value={password}
        onChange={setPassword}
        autoComplete="current-password"
        disabled={exportAction.busy}
      />
      <label className="checkbox">
        <input
          type="checkbox"
          checked={acknowledged}
          disabled={exportAction.busy}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        <span>{t.transfer.exportAcknowledge}</span>
      </label>
      <ErrorMessage message={exportAction.error} />
      {exported !== null ? (
        <p role="status" className="message info">
          {t.transfer.exported(exported)}
        </p>
      ) : null}
      <div className="row">
        <button
          type="button"
          className="secondary"
          disabled={
            exportAction.busy || !acknowledged || password === '' || state.entries.length === 0
          }
          onClick={() => doExport('json')}
        >
          {exportAction.busy ? t.transfer.exportWorking : t.transfer.exportJson}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={
            exportAction.busy || !acknowledged || password === '' || state.entries.length === 0
          }
          onClick={() => doExport('csv')}
        >
          {t.transfer.exportCsv}
        </button>
      </div>

      <hr className="divider" />

      <h3>{t.transfer.importTitle}</h3>
      <p className="hint">{t.transfer.importIntro}</p>
      <div className="field">
        <label htmlFor="import-file">{t.transfer.chooseFile}</label>
        <input
          id="import-file"
          ref={fileInput}
          type="file"
          accept=".json,.csv,application/json,text/csv"
          disabled={importAction.busy}
          onChange={(event) => void chooseFile(event.target.files?.[0])}
        />
      </div>
      <ErrorMessage message={fileError ?? importAction.error} />
      {parsed ? (
        <>
          <p role="status">{t.transfer.found(parsed.items.length, parsed.skipped)}</p>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={skipDuplicates}
              disabled={importAction.busy}
              onChange={(event) => setSkipDuplicates(event.target.checked)}
            />
            <span>{t.transfer.skipDuplicates}</span>
          </label>
          <button type="button" disabled={importAction.busy} onClick={doImport}>
            {t.transfer.importButton(parsed.items.length)}
          </button>
        </>
      ) : null}
      {progress ? (
        <p role="status" className="hint">
          {t.transfer.progress(progress.done, progress.total)}
        </p>
      ) : null}
      {outcome ? (
        <p role="status" className="message info">
          {t.transfer.result(outcome.created, outcome.failed, outcome.duplicates)}
        </p>
      ) : null}
      {stoppedText ? <p className="message error">{stoppedText}</p> : null}
    </div>
  );
}

function DeletePanel() {
  const store = useAuthStore();
  const { busy, error, run } = useAction();
  const [password, setPassword] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void run(() => store.deleteAccount(password));
  };

  return (
    <form onSubmit={submit} className="stack" noValidate>
      <h3>{t.account.delete.title}</h3>
      <p className="message error">{t.account.delete.warning}</p>
      <PasswordField
        label={t.account.delete.password}
        value={password}
        onChange={setPassword}
        autoComplete="current-password"
        disabled={busy}
      />
      <label className="checkbox">
        <input
          type="checkbox"
          checked={acknowledged}
          disabled={busy}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        <span>{t.account.delete.acknowledge}</span>
      </label>
      <ErrorMessage message={error} />
      <button type="submit" className="danger" disabled={busy || password === '' || !acknowledged}>
        {busy ? t.account.delete.working : t.account.delete.submit}
      </button>
    </form>
  );
}

export function AccountScreen({ vault, onBack }: { vault: VaultStore; onBack: () => void }) {
  const [panel, setPanel] = useState<Panel>('sessions');
  const tabs: readonly { id: Panel; label: string }[] = [
    { id: 'sessions', label: t.account.tabs.sessions },
    { id: 'password', label: t.account.tabs.password },
    { id: 'transfer', label: t.account.tabs.transfer },
    { id: 'delete', label: t.account.tabs.delete },
  ];

  return (
    <div className="stack">
      <h2>{t.account.title}</h2>
      <div className="tabs" role="tablist">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={panel === tab.id}
            onClick={() => setPanel(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {panel === 'sessions' ? <SessionsPanel /> : null}
      {panel === 'password' ? <ChangePasswordPanel /> : null}
      {panel === 'transfer' ? <TransferPanel vault={vault} /> : null}
      {panel === 'delete' ? <DeletePanel /> : null}
      <button type="button" className="secondary" onClick={onBack}>
        {t.account.back}
      </button>
    </div>
  );
}
