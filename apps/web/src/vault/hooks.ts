import { useEffect, useRef, useSyncExternalStore } from 'react';
import type { VaultState, VaultStore } from './store';

export const IDLE_LOCK_MS = 5 * 60_000;
export const SYNC_INTERVAL_MS = 60_000;

export function useVaultState(vault: VaultStore): VaultState {
  return useSyncExternalStore(vault.subscribe, vault.getState);
}

const ACTIVITY_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart'] as const;

// Zakljucava posle `timeoutMs` bez aktivnosti. Pamti se samo vreme poslednje aktivnosti, a jedan
// tajmer proverava koliko je proslo: pregledac usporava tajmere u pozadini, pa se pri povratku na
// karticu isto proverava odmah.
export function useIdleLock(onIdle: () => void, timeoutMs: number = IDLE_LOCK_MS): void {
  const callback = useRef(onIdle);
  useEffect(() => {
    callback.current = onIdle;
  }, [onIdle]);

  useEffect(() => {
    let lastActivity = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;

    const check = () => {
      clearTimeout(timer);
      const idle = Date.now() - lastActivity;
      if (idle >= timeoutMs) {
        callback.current();
        return;
      }
      timer = setTimeout(check, timeoutMs - idle);
    };
    const touch = () => {
      lastActivity = Date.now();
    };

    for (const name of ACTIVITY_EVENTS) {
      window.addEventListener(name, touch, { passive: true });
    }
    document.addEventListener('visibilitychange', check);
    timer = setTimeout(check, timeoutMs);
    return () => {
      clearTimeout(timer);
      for (const name of ACTIVITY_EVENTS) {
        window.removeEventListener(name, touch);
      }
      document.removeEventListener('visibilitychange', check);
    };
  }, [timeoutMs]);
}

// Osvezava vault: pri otvaranju, kad se vratite na karticu i na svakih SYNC_INTERVAL_MS dok je
// kartica vidljiva. VaultStore.sync() je jedan zahtev odjednom, pa cesti okidaci nista ne kvare.
export function useVaultSync(vault: VaultStore, intervalMs: number = SYNC_INTERVAL_MS): void {
  useEffect(() => {
    void vault.sync();
    const refresh = () => {
      if (document.visibilityState === 'visible') {
        void vault.sync();
      }
    };
    const interval = setInterval(refresh, intervalMs);
    window.addEventListener('focus', refresh);
    document.addEventListener('visibilitychange', refresh);
    return () => {
      clearInterval(interval);
      window.removeEventListener('focus', refresh);
      document.removeEventListener('visibilitychange', refresh);
    };
  }, [vault, intervalMs]);
}
