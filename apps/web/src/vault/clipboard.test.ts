import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CLIPBOARD_CLEAR_MS, ClipboardGuard, ClipboardUnavailableError } from './clipboard';

class FakeClipboard {
  writes: string[] = [];
  failNext = false;
  async writeText(text: string): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      throw new DOMException('Document is not focused', 'NotAllowedError');
    }
    this.writes.push(text);
  }
}

describe('ClipboardGuard', () => {
  let clipboard: FakeClipboard;
  let guard: ClipboardGuard;

  beforeEach(() => {
    vi.useFakeTimers();
    clipboard = new FakeClipboard();
    guard = new ClipboardGuard({ clipboard });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('kopira, a tajnu brise tek posle 30 sekundi', async () => {
    await guard.copy('tajna');
    expect(clipboard.writes).toEqual(['tajna']);

    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS - 1);
    expect(clipboard.writes).toEqual(['tajna']);
    await vi.advanceTimersByTimeAsync(1);
    expect(clipboard.writes).toEqual(['tajna', '']);

    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS * 3);
    expect(clipboard.writes).toEqual(['tajna', '']); // samo jednom
  });

  it('novo kopiranje resetuje odbrojavanje (prva tajna ne brise drugu prerano)', async () => {
    await guard.copy('prva');
    await vi.advanceTimersByTimeAsync(20_000);
    await guard.copy('druga');
    await vi.advanceTimersByTimeAsync(20_000);
    expect(clipboard.writes).toEqual(['prva', 'druga']);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(clipboard.writes).toEqual(['prva', 'druga', '']);
  });

  it('obican tekst (korisnicko ime) se ne brise', async () => {
    await guard.copy('marko', false);
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS * 2);
    expect(clipboard.writes).toEqual(['marko']);
  });

  it('kopiranje obicnog teksta otkazuje brisanje ranije tajne (klipbord vise nije tajna)', async () => {
    await guard.copy('tajna');
    await guard.copy('marko', false);
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS * 2);
    await guard.flush(); // ni zakljucavanje ne sme da obrise korisnicko ime kao da je tajna
    expect(clipboard.writes).toEqual(['tajna', 'marko']);
  });

  it('flush brise odmah, i to samo ako ima sta da se brise', async () => {
    await guard.flush();
    expect(clipboard.writes).toEqual([]);

    await guard.copy('tajna');
    await guard.flush();
    expect(clipboard.writes).toEqual(['tajna', '']);
    await guard.flush();
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS * 2);
    expect(clipboard.writes).toEqual(['tajna', '']);
  });

  it('ako pregledac odbije brisanje (nema fokusa), ponovo pokusava kad se fokus vrati', async () => {
    await guard.copy('tajna');
    clipboard.failNext = true;
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
    expect(clipboard.writes).toEqual(['tajna']);

    window.dispatchEvent(new Event('focus'));
    await vi.advanceTimersByTimeAsync(0);
    expect(clipboard.writes).toEqual(['tajna', '']);

    // Uspelo je, pa dalji fokus nista ne radi.
    window.dispatchEvent(new Event('focus'));
    await vi.advanceTimersByTimeAsync(0);
    expect(clipboard.writes).toEqual(['tajna', '']);
  });

  it('neuspelo kopiranje ne pokrece brisanje i greska stize do pozivaoca', async () => {
    clipboard.failNext = true;
    await expect(guard.copy('tajna')).rejects.toBeInstanceOf(DOMException);
    await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS * 2);
    expect(clipboard.writes).toEqual([]);
  });

  it('bez klipborda u pregledacu baca ClipboardUnavailableError', async () => {
    const original = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    try {
      await expect(new ClipboardGuard().copy('x')).rejects.toBeInstanceOf(
        ClipboardUnavailableError,
      );
    } finally {
      if (original) Object.defineProperty(navigator, 'clipboard', original);
      else delete (navigator as unknown as Record<string, unknown>)['clipboard'];
    }
  });
});
