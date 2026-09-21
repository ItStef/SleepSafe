import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('@sleepsafe/shared/jitless', () => {
  const original = globalThis.Function;
  let calls = 0;

  beforeEach(() => {
    vi.resetModules();
    calls = 0;
    globalThis.Function = new Proxy(original, {
      construct(target, args, newTarget) {
        calls += 1;
        return Reflect.construct(target, args, newTarget);
      },
      apply(target, thisArg, args) {
        calls += 1;
        return Reflect.apply(target, thisArg, args);
      },
    });
  });

  afterEach(() => {
    globalThis.Function = original;
  });

  it('bez ovog modula Zod pokusava da kompajlira provere (polazna tacka testa)', async () => {
    const { z } = await import('zod');
    z.strictObject({ a: z.string() }).parse({ a: 'x' });
    expect(calls).toBeGreaterThan(0);
  });

  it('sa ovim modulom uvezenim prvo, nijedna sema iz paketa ne dodiruje `new Function`', async () => {
    await import('../jitless');
    const { registerRequestSchema, recoveryStartRequestSchema, itemDataSchema } =
      await import('../index');
    expect(recoveryStartRequestSchema.safeParse({ email: 'a@example.com' }).success).toBe(true);
    expect(
      itemDataSchema.safeParse({ title: 'x', username: '', password: '', url: '', notes: '' })
        .success,
    ).toBe(true);
    expect(registerRequestSchema.safeParse({}).success).toBe(false);
    expect(calls).toBe(0);
  });
});
