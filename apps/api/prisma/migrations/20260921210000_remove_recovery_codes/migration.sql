DROP TABLE "recovery_codes";

ALTER TABLE "users"
  DROP COLUMN "recoverySalt",
  DROP COLUMN "recoveryKdfMemoryKiB",
  DROP COLUMN "recoveryKdfIterations",
  DROP COLUMN "recoveryKdfParallelism";

DELETE FROM "otp_challenges" WHERE "purpose" IN ('RECOVERY', 'RECOVERY_RESET');

ALTER TYPE "OtpPurpose" RENAME TO "OtpPurpose_old";
CREATE TYPE "OtpPurpose" AS ENUM ('EMAIL_VERIFICATION', 'LOGIN');
ALTER TABLE "otp_challenges"
  ALTER COLUMN "purpose" TYPE "OtpPurpose" USING ("purpose"::text::"OtpPurpose");
DROP TYPE "OtpPurpose_old";