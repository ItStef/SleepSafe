interface Entry {
  count: number;
  windowStart: number;
}

export class FailureThrottle {
  private readonly entries = new Map<string, Entry>();

  constructor(
    private readonly maxFailures: number,
    private readonly windowMs: number,
    private readonly maxEntries = 10_000,
  ) {}

  isBlocked(key: string, now: Date): boolean {
    const entry = this.current(key, now.getTime());
    return entry !== undefined && entry.count >= this.maxFailures;
  }

  recordFailure(key: string, now: Date): void {
    const time = now.getTime();
    const entry = this.current(key, time);
    if (entry) {
      entry.count += 1;
      return;
    }
    if (this.entries.size >= this.maxEntries) {
      this.evict(time);
    }
    this.entries.set(key, { count: 1, windowStart: time });
  }

  get size(): number {
    return this.entries.size;
  }

  private current(key: string, time: number): Entry | undefined {
    const entry = this.entries.get(key);
    if (entry && time - entry.windowStart >= this.windowMs) {
      this.entries.delete(key);
      return undefined;
    }
    return entry;
  }

  private evict(time: number): void {
    for (const [key, entry] of this.entries) {
      if (time - entry.windowStart >= this.windowMs) {
        this.entries.delete(key);
      }
    }
    if (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (!oldest.done) {
        this.entries.delete(oldest.value);
      }
    }
  }
}
