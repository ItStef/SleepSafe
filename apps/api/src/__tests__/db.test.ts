import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Prisma, type PrismaClient, createPrismaClient } from '../db';

const databaseUrl = process.env['DATABASE_URL'];

describe.skipIf(!databaseUrl)('baza podataka', () => {
  let prisma: PrismaClient;
  const createdUserIds: string[] = [];

  const envelope = {
    v: 1,
    iv: 'AAAAAAAAAAAAAAAA',
    ct: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  };

  function newUserData() {
    return {
      email: `test-${randomUUID()}@example.com`,
      authHash: '$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA',
      kdfSalt: 'c2FsdHNhbHRzYWx0c2FsdA',
      kdfMemoryKiB: 65536,
      kdfIterations: 3,
      kdfParallelism: 1,
      wrappedVaultKey: envelope,
    };
  }

  async function createUser() {
    const user = await prisma.user.create({ data: newUserData() });
    createdUserIds.push(user.id);
    return user;
  }

  beforeAll(() => {
    prisma = createPrismaClient(databaseUrl as string);
  });

  afterAll(async () => {
    await prisma.user.deleteMany({ where: { id: { in: createdUserIds } } });
    await prisma.$disconnect();
  });

  it('povezuje se i izvrsava upit', async () => {
    const rows = await prisma.$queryRaw<{ ok: number }[]>`SELECT 1 AS ok`;
    expect(rows[0]?.ok).toBe(1);
  });

  it('cuva korisnika i vraca JSON omotnicu neizmenjenu', async () => {
    const user = await createUser();
    const found = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(found.wrappedVaultKey).toEqual(envelope);
    expect(found.kdfMemoryKiB).toBe(65536);
    expect(found.emailVerifiedAt).toBeNull();
  });

  it('ID-jevi su UUID verzije 7 (vremenski uredjeni)', async () => {
    const user = await createUser();
    expect(user.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('ne dozvoljava dva korisnika sa istim emailom', async () => {
    const user = await createUser();
    const duplicate = prisma.user.create({ data: { ...newUserData(), email: user.email } });
    await expect(duplicate).rejects.toBeInstanceOf(Prisma.PrismaClientKnownRequestError);
    await expect(duplicate).rejects.toMatchObject({ code: 'P2002' });
  });

  it('refresh token heš je jedinstven', async () => {
    const user = await createUser();
    const data = {
      userId: user.id,
      refreshTokenHash: `hash-${randomUUID()}`,
      expiresAt: new Date(Date.now() + 60_000),
    };
    await prisma.session.create({ data });
    await expect(prisma.session.create({ data })).rejects.toMatchObject({ code: 'P2002' });
  });

  it('brisanje korisnika brise sesije, OTP kodove i stavke (kaskadno)', async () => {
    const user = await createUser();
    await prisma.session.create({
      data: {
        userId: user.id,
        refreshTokenHash: `hash-${randomUUID()}`,
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    await prisma.otpChallenge.create({
      data: {
        userId: user.id,
        purpose: 'LOGIN',
        codeHash: 'h',
        expiresAt: new Date(Date.now() + 60_000),
      },
    });
    await prisma.vaultItem.create({
      data: { id: randomUUID(), userId: user.id, revision: 1, envelope },
    });

    await prisma.user.delete({ where: { id: user.id } });

    expect(await prisma.session.count({ where: { userId: user.id } })).toBe(0);
    expect(await prisma.otpChallenge.count({ where: { userId: user.id } })).toBe(0);
    expect(await prisma.vaultItem.count({ where: { userId: user.id } })).toBe(0);
  });

  it('sinhronizacija: vraca samo stavke izmenjene posle zadatog kursora, ukljucujuci obrisane', async () => {
    const user = await createUser();
    const oldId = randomUUID();
    const newId = randomUUID();
    await prisma.vaultItem.create({ data: { id: oldId, userId: user.id, revision: 1, envelope } });
    await prisma.vaultItem.create({ data: { id: newId, userId: user.id, revision: 2, envelope } });
    await prisma.vaultItem.update({
      where: { userId_id: { userId: user.id, id: oldId } },
      data: { envelope: Prisma.DbNull, deletedAt: new Date(), revision: 3 },
    });

    const changed = await prisma.vaultItem.findMany({
      where: { userId: user.id, revision: { gt: 1 } },
      orderBy: { revision: 'asc' },
    });

    expect(changed.map((item) => item.id)).toEqual([newId, oldId]);
    expect(changed[1]?.deletedAt).not.toBeNull();
    expect(changed[1]?.envelope).toBeNull();
    expect(changed[1]?.revision).toBe(3);
  });

  it('isti ID stavke moze postojati kod dva korisnika, ali ne dvaput kod istog', async () => {
    const first = await createUser();
    const second = await createUser();
    const id = randomUUID();
    await prisma.vaultItem.create({ data: { id, userId: first.id, revision: 1, envelope } });
    await prisma.vaultItem.create({ data: { id, userId: second.id, revision: 1, envelope } });

    await expect(
      prisma.vaultItem.create({ data: { id, userId: first.id, revision: 2, envelope } }),
    ).rejects.toMatchObject({ code: 'P2002' });
  });

  it('dve stavke istog korisnika ne mogu imati isti revision', async () => {
    const user = await createUser();
    await prisma.vaultItem.create({
      data: { id: randomUUID(), userId: user.id, revision: 1, envelope },
    });
    await expect(
      prisma.vaultItem.create({
        data: { id: randomUUID(), userId: user.id, revision: 1, envelope },
      }),
    ).rejects.toMatchObject({ code: 'P2002' });
  });

  it('updatedAt se menja pri izmeni, a createdAt ne', async () => {
    const user = await createUser();
    const id = randomUUID();
    const item = await prisma.vaultItem.create({
      data: { id, userId: user.id, revision: 1, envelope },
    });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const updated = await prisma.vaultItem.update({
      where: { userId_id: { userId: user.id, id } },
      data: {
        envelope: { ...envelope, ct: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' },
      },
    });
    expect(updated.updatedAt.getTime()).toBeGreaterThan(item.updatedAt.getTime());
    expect(updated.createdAt.getTime()).toBe(item.createdAt.getTime());
  });
});
