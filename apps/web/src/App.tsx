import { useAuthState, useAuthStore } from './auth/context';
import { CodeScreen } from './screens/CodeScreen';
import { SignedOutScreen } from './screens/SignedOutScreen';
import {
  RecoveryCodeScreen,
  RecoveryCodesScreen,
  RecoveryPasswordScreen,
} from './screens/RecoveryScreens';
import { UnlockScreen } from './screens/UnlockScreen';
import { VaultScreen } from './screens/VaultScreen';
import { t } from './strings';

function Screen() {
  const store = useAuthStore();
  const state = useAuthState();

  switch (state.status) {
    case 'booting':
      return <p className="hint">{t.loading}</p>;
    case 'signedOut':
      return <SignedOutScreen notice={state.notice} />;
    case 'recoveryCodes':
      return <RecoveryCodesScreen email={state.email} codes={state.codes} />;
    case 'recoveryOtp':
      return (
        <CodeScreen
          title={t.recover.otpTitle}
          intro={t.recover.otpIntro(state.email)}
          onSubmit={(code) => store.submitRecoveryOtp(code)}
          onResend={() => store.resendRecoveryOtp()}
          onBack={() => store.cancelPending()}
        />
      );
    case 'recoveryCode':
      return <RecoveryCodeScreen />;
    case 'recoveryPassword':
      return <RecoveryPasswordScreen />;
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
      return <VaultScreen user={state.user} vault={state.vault} />;
  }
}

export function App() {
  const state = useAuthState();
  return (
    <main className="shell">
      <header className="brand">
        <h1>{t.appName}</h1>
        <p>{t.tagline}</p>
      </header>
      <section className={state.status === 'unlocked' ? 'card wide' : 'card'}>
        <Screen />
      </section>
    </main>
  );
}
