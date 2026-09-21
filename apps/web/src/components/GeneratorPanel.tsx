import { useId, useState } from 'react';
import { t } from '../strings';
import {
  DEFAULT_GENERATOR,
  GENERATOR_LIMITS,
  type GeneratorOptions,
  estimateEntropyBits,
  generatePassword,
  isGeneratorValid,
} from '../vault/generator';

type Toggle = 'lower' | 'upper' | 'digits' | 'symbols' | 'avoidAmbiguous';

const TOGGLES: readonly { key: Toggle; label: string }[] = [
  { key: 'lower', label: t.generator.lower },
  { key: 'upper', label: t.generator.upper },
  { key: 'digits', label: t.generator.digits },
  { key: 'symbols', label: t.generator.symbols },
  { key: 'avoidAmbiguous', label: t.generator.avoidAmbiguous },
];

export function GeneratorPanel({ onUse }: { onUse: (password: string) => void }) {
  const lengthId = useId();
  const [options, setOptions] = useState<GeneratorOptions>(DEFAULT_GENERATOR);
  const [lengthText, setLengthText] = useState(String(DEFAULT_GENERATOR.length));
  const [suggestion, setSuggestion] = useState(() => generatePassword(DEFAULT_GENERATOR));
  const valid = isGeneratorValid(options);

  const change = (patch: Partial<GeneratorOptions>) => {
    const next = { ...options, ...patch };
    setOptions(next);
    if (isGeneratorValid(next)) {
      setSuggestion(generatePassword(next));
    }
  };

  const changeLength = (text: string) => {
    setLengthText(text);
    change({ length: text.trim() === '' ? Number.NaN : Number(text) });
  };

  return (
    <fieldset className="generator">
      <legend>{t.form.generator}</legend>
      <div className="field">
        <label htmlFor={lengthId}>{t.generator.length}</label>
        <input
          id={lengthId}
          type="number"
          inputMode="numeric"
          min={GENERATOR_LIMITS.minLength}
          max={GENERATOR_LIMITS.maxLength}
          value={lengthText}
          onChange={(event) => changeLength(event.target.value)}
        />
      </div>
      {TOGGLES.map(({ key, label }) => (
        <label key={key} className="checkbox">
          <input
            type="checkbox"
            checked={options[key]}
            onChange={(event) => change({ [key]: event.target.checked })}
          />
          <span>{label}</span>
        </label>
      ))}
      {valid ? (
        <>
          <p className="generated" data-testid="generated-password">
            {suggestion}
          </p>
          <p className="hint">{t.generator.entropy(estimateEntropyBits(options))}</p>
        </>
      ) : (
        <p role="alert" className="message error">
          {t.generator.invalid(GENERATOR_LIMITS.minLength, GENERATOR_LIMITS.maxLength)}
        </p>
      )}
      <div className="row">
        <button
          type="button"
          className="secondary"
          disabled={!valid}
          onClick={() => setSuggestion(generatePassword(options))}
        >
          {t.generator.regenerate}
        </button>
        <button type="button" disabled={!valid} onClick={() => onUse(suggestion)}>
          {t.generator.use}
        </button>
      </div>
    </fieldset>
  );
}
