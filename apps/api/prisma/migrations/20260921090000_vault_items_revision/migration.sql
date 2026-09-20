-- DropIndex
DROP INDEX "vault_items_userId_updatedAt_idx";

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "vaultRevision" INTEGER NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE "vault_items" DROP CONSTRAINT "vault_items_pkey",
DROP COLUMN "version",
ADD COLUMN     "revision" INTEGER NOT NULL,
ALTER COLUMN "envelope" DROP NOT NULL,
ADD CONSTRAINT "vault_items_pkey" PRIMARY KEY ("userId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "vault_items_userId_revision_key" ON "vault_items"("userId", "revision");
