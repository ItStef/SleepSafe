import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createAuthApi } from './api/auth';
import { HttpClient } from './api/http';
import { createVaultApi } from './api/vault';
import { AuthProvider } from './auth/context';
import { AuthStore } from './auth/store';
import { createWorkerDeriver } from './crypto/deriver';
import './styles.css';

const http = new HttpClient();
const store = new AuthStore({
  api: createAuthApi(http),
  vaultApi: createVaultApi(http),
  deriver: createWorkerDeriver(),
});
http.onSessionExpired = () => store.sessionExpired();
void store.boot();

const root = document.getElementById('root');
if (!root) {
  throw new Error('Missing #root element');
}
createRoot(root).render(
  <StrictMode>
    <AuthProvider store={store}>
      <App />
    </AuthProvider>
  </StrictMode>,
);
