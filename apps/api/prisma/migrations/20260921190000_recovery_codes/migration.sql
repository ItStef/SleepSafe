-- AlterEnum
ALTER TYPE "OtpPurpose" ADD VALUE 'RECOVERY';
ALTER TYPE "OtpPurpose" ADD VALUE 'RECOVERY_RESET';

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "recoveryKdfIterations" INTEGER,
ADD COLUMN     "recoveryKdfMemoryKiB" INTEGER,
ADD COLUMN     "recoveryKdfParallelism" INTEGER,
ADD COLUMN     "recoverySalt" TEXT;

-- CreateTable
CREATE TABLE "recovery_codes" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "codeHash" TEXT NOT NULL,
    "wrappedVaultKey" JSONB NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "recovery_codes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "recovery_codes_userId_idx" ON "recovery_codes"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "recovery_codes_userId_codeHash_key" ON "recovery_codes"("userId", "codeHash");

-- AddForeignKey
ALTER TABLE "recovery_codes" ADD CONSTRAINT "recovery_codes_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
