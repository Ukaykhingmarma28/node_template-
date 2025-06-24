import { DataSource } from 'typeorm';

import { User } from '../services/users/userEntity';

export const AppDataSource = new DataSource({
  type: 'postgres',
  database: 'jadupc',
  host: 'localhost',
  port: 5432,
  username: 'postgres',
  password: 'admin123',
  entities: [User],
  migrations: [__dirname + '/../database/migrations/*.ts'],
  migrationsTableName: 'migrations',
  synchronize: false,
});