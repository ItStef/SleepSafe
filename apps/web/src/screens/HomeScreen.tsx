import { useAuthStore } from '../auth/context';
import type { SessionUser } from '../auth/store';
import { t } from '../strings';

export function HomeScreen({ user }: { user: SessionUser }) {
  const store = useAuthStore();
  return (
    <div className="stack">
      <h2>{t.home.title}</h2>
      <p className="hint">{t.home.signedInAs(user.email)}</p>
      <p>{t.home.body}</p>
      <div className="row">
        <button type="button" className="secondary" onClick={() => store.lock()}>
          {t.home.lock}
        </button>
        <button type="button" className="secondary" onClick={() => void store.logout()}>
          {t.home.logout}
        </button>
      </div>
    </div>
  );
}
