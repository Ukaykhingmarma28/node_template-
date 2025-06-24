import { Entity, PrimaryGeneratedColumn, Column, BaseEntity } from 'typeorm';

@Entity()
export class User extends BaseEntity {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column()
  name!: string;

  @Column({ nullable: true })
  email?: string;

  @Column()
  password!: string;

  @Column({ unique: true })
  phoneNumber!: string;

  @Column({ nullable: true })
  address?: string;

  @Column()
  role!: 'guest' | 'registered_user' | 'admin';

  @Column({ nullable: true })
  resetCode?: string;

  @Column({ nullable: true })
  resetCodeExpiresAt?: Date;

  @Column({ nullable: true })
  passwordResetToken?: string;

  @Column({ nullable: true })
  passwordResetExpires?: Date;
}