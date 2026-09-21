export const CLIPBOARD_CLEAR_MS = 30_000;

export interface ClipboardLike {
  writeText(text: string): Promise<void>;
}

export class ClipboardUnavailableError extends Error {
  constructor() {
    super('Clipboard is not available');
    this.name = 'ClipboardUnavailableError';
  }
}

// Kopira tajne u klipbord i brise ih posle CLIPBOARD_CLEAR_MS. Klipbord se ne cita nazad (to trazi
// dozvolu i pokazuje upozorenje u pregledacu), pa se brise samo ono sto je ovaj vault poslednje
// kopirao: svako novo kopiranje resetuje odbrojavanje.
export class ClipboardGuard {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private pending = false;
  private readonly retry = () => {
    void this.flush();
  };

  constructor(
    private readonly options: { clipboard?: ClipboardLike | undefined; clearAfterMs?: number } = {},
  ) {}

  private clipboard(): ClipboardLike {
    const clipboard =
      this.options.clipboard ??
      (typeof navigator === 'undefined' ? undefined : navigator.clipboard);
    if (!clipboard) {
      throw new ClipboardUnavailableError();
    }
    return clipboard;
  }

  // sensitive=false: obican tekst (korisnicko ime), ostaje u klipbordu.
  async copy(text: string, sensitive = true): Promise<void> {
    await this.clipboard().writeText(text);
    this.cancelTimer();
    // Obican tekst je prepisao tajnu, pa vise nema sta da se brise.
    this.pending = sensitive;
    if (!sensitive) {
      return;
    }
    this.timer = setTimeout(() => {
      void this.flush();
    }, this.options.clearAfterMs ?? CLIPBOARD_CLEAR_MS);
  }

  // Brise odmah ono sto smo kopirali (na primer pri zakljucavanju). Pregledac odbija upis dok
  // stranica nije u fokusu, pa se u tom slucaju pokusava ponovo cim se fokus vrati.
  async flush(): Promise<void> {
    this.cancelTimer();
    window.removeEventListener('focus', this.retry);
    if (!this.pending) {
      return;
    }
    try {
      await this.clipboard().writeText('');
      this.pending = false;
    } catch {
      window.addEventListener('focus', this.retry);
    }
  }

  private cancelTimer(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
