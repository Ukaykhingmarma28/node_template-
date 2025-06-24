import { MigrationInterface, QueryRunner } from "typeorm";

export class Userforgetpassword1750800138386 implements MigrationInterface {
    name = 'Userforgetpassword1750800138386'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "user" ADD "resetCode" character varying`);
        await queryRunner.query(`ALTER TABLE "user" ADD "resetCodeExpiresAt" TIMESTAMP`);
        await queryRunner.query(`ALTER TABLE "user" ADD "passwordResetToken" character varying`);
        await queryRunner.query(`ALTER TABLE "user" ADD "passwordResetExpires" TIMESTAMP`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "passwordResetExpires"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "passwordResetToken"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "resetCodeExpiresAt"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "resetCode"`);
    }

}
