import { type ReactNode, createContext, useContext, useSyncExternalStore } from 'react';
import type { AuthState, AuthStore } from './store';

const AuthContext = createContext<AuthStore | null>(null);

export function AuthProvider({ store, children }: { store: AuthStore; children: ReactNode }) {
  return <AuthContext.Provider value={store}>{children}</AuthContext.Provider>;
}

export function useAuthStore(): AuthStore {
  const store = useContext(AuthContext);
  if (!store) {
    throw new Error('useAuthStore must be used inside <AuthProvider>');
  }
  return store;
}

export function useAuthState(): AuthState {
  const store = useAuthStore();
  return useSyncExternalStore(store.subscribe, store.getState);
}
