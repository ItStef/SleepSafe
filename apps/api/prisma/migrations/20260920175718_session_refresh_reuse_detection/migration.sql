-- AlterTable
ALTER TABLE "sessions" ADD COLUMN     "previousRefreshTokenHash" TEXT;

-- CreateIndex
CREATE INDEX "sessions_previousRefreshTokenHash_idx" ON "sessions"("previousRefreshTokenHash");
