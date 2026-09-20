import { useAuthState, useAuthStore } from './auth/context';
import { CodeScreen } from './screens/CodeScreen';
import { HomeScreen } from './screens/HomeScreen';
import { SignedOutScreen } from './screens/SignedOutScreen';
import { UnlockScreen } from './screens/UnlockScreen';
import { t } from './strings';

function Screen() {
  const store = useAuthStore();
  const state = useAuthState();

  switch (state.status) {
    case 'booting':
      return <p className="hint">{t.loading}</p>;
    case 'signedOut':
      return <SignedOutScreen notice={state.notice} />;
    case 'verifyingEmail':
      return (
        <CodeScreen
          title={t.code.verifyEmailTitle}
          intro={t.code.verifyEmailIntro(state.email)}
          onSubmit={(code) => store.verifyEmail(code)}
          onResend={() => store.resendVerification()}
          onBack={() => store.cancelPending()}
        />
      );
    case 'loginCode':
      return (
        <CodeScreen
          title={t.code.loginTitle}
          intro={t.code.loginIntro(state.email)}
          onSubmit={(code) => store.verifyLoginCode(code)}
          onResend={() => store.resendLoginCode()}
          onBack={() => store.cancelPending()}
        />
      );
    case 'locked':
      return <UnlockScreen email={state.email} />;
    case 'unlocked':
      return <HomeScreen user={state.user} />;
  }
}

export function App() {
  return (
    <main className="shell">
      <header className="brand">
        <h1>{t.appName}</h1>
        <p>{t.tagline}</p>
      </header>
      <section className="card">
        <Screen />
      </section>
    </main>
  );
}
