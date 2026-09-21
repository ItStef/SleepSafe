import { useId, useState } from 'react';
import { t } from '../strings';

interface FieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete: string;
  disabled?: boolean;
  autoFocus?: boolean;
  maxLength?: number;
}

export function TextField({
  label,
  value,
  onChange,
  autoComplete,
  type = 'text',
  disabled,
  autoFocus,
  maxLength,
}: FieldProps & { type?: 'text' | 'email' | 'search' }) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        type={type}
        value={value}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        disabled={disabled}
        maxLength={maxLength}
        spellCheck={false}
        autoCapitalize="none"
        onChange={(event) => onChange(event.target.value)}
      />
    </div>
  );
}

export function TextAreaField({
  label,
  value,
  onChange,
  disabled,
  maxLength,
}: Omit<FieldProps, 'autoComplete' | 'autoFocus'>) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <textarea
        id={id}
        value={value}
        rows={4}
        disabled={disabled}
        maxLength={maxLength}
        onChange={(event) => onChange(event.target.value)}
      />
    </div>
  );
}

export function PasswordField({
  label,
  value,
  onChange,
  autoComplete,
  disabled,
  autoFocus,
  maxLength,
}: FieldProps) {
  const id = useId();
  const [visible, setVisible] = useState(false);
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="password-row">
        <input
          id={id}
          type={visible ? 'text' : 'password'}
          value={value}
          autoComplete={autoComplete}
          autoFocus={autoFocus}
          disabled={disabled}
          maxLength={maxLength}
          spellCheck={false}
          autoCapitalize="none"
          onChange={(event) => onChange(event.target.value)}
        />
        <button
          type="button"
          className="secondary small"
          aria-pressed={visible}
          onClick={() => setVisible((current) => !current)}
        >
          {visible ? t.fields.hide : t.fields.show}
        </button>
      </div>
    </div>
  );
}

export function ErrorMessage({ message }: { message: string | null }) {
  return message ? (
    <p role="alert" className="message error">
      {message}
    </p>
  ) : null;
}
