import { ITEM_LIMITS, type ItemData, emptyItemData } from '@sleepsafe/shared';
import { type FormEvent, useState } from 'react';
import { ErrorMessage, PasswordField, TextAreaField, TextField } from '../components/Fields';
import { GeneratorPanel } from '../components/GeneratorPanel';
import { useAction } from '../hooks';
import { t } from '../strings';
import type { VaultEntry, VaultStore } from '../vault/store';

interface ItemFormProps {
  vault: VaultStore;
  // Bez stavke je nova stavka, sa stavkom je izmena.
  entry?: VaultEntry;
  onDone: (id: string) => void;
  onCancel: () => void;
}

export function ItemForm({ vault, entry, onDone, onCancel }: ItemFormProps) {
  const { busy, error, run } = useAction();
  const [data, setData] = useState<ItemData>(() => (entry ? { ...entry.data } : emptyItemData()));
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const set = (patch: Partial<ItemData>) => setData((current) => ({ ...current, ...patch }));

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void run(async () => {
      if (entry) {
        await vault.update(entry.id, data);
        onDone(entry.id);
      } else {
        onDone(await vault.create(data));
      }
    });
  };

  return (
    <form onSubmit={submit} className="stack">
      <h2>{entry ? t.form.editTitle : t.form.newTitle}</h2>
      <TextField
        label={t.form.title}
        value={data.title}
        onChange={(title) => set({ title })}
        autoComplete="off"
        maxLength={ITEM_LIMITS.title}
        disabled={busy}
        autoFocus
      />
      <TextField
        label={t.item.username}
        value={data.username}
        onChange={(username) => set({ username })}
        autoComplete="off"
        maxLength={ITEM_LIMITS.username}
        disabled={busy}
      />
      <PasswordField
        label={t.item.password}
        value={data.password}
        onChange={(password) => set({ password })}
        autoComplete="new-password"
        maxLength={ITEM_LIMITS.password}
        disabled={busy}
      />
      <button
        type="button"
        className="secondary small"
        aria-expanded={generatorOpen}
        disabled={busy}
        onClick={() => setGeneratorOpen((open) => !open)}
      >
        {generatorOpen ? t.form.hideGenerator : t.form.generator}
      </button>
      {generatorOpen && (
        <GeneratorPanel
          onUse={(password) => {
            set({ password });
            setGeneratorOpen(false);
          }}
        />
      )}
      <TextField
        label={t.item.url}
        value={data.url}
        onChange={(url) => set({ url })}
        autoComplete="off"
        maxLength={ITEM_LIMITS.url}
        disabled={busy}
      />
      <TextAreaField
        label={t.item.notes}
        value={data.notes}
        onChange={(notes) => set({ notes })}
        maxLength={ITEM_LIMITS.notes}
        disabled={busy}
      />
      <ErrorMessage message={error} />
      <div className="row">
        <button type="button" className="secondary" disabled={busy} onClick={onCancel}>
          {t.form.cancel}
        </button>
        <button type="submit" disabled={busy || data.title.trim() === ''}>
          {busy ? t.form.saving : t.form.save}
        </button>
      </div>
    </form>
  );
}
