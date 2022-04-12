import config from '../../config';
const Sequelize = require('sequelize');

export default class DB {
  public db: any;
  constructor() {
    try {
      const sequelize = new Sequelize(
        config.PG_DATABASE,
        config.PG_USER,
        config.PG_PASSWORD,
        {
          host: config.PG_HOST,
          dialect: 'postgres',
          pool: { max: 5, min: 0, ideal: 1000 },
          logging: false,
          port: config.PG_PORT,
          dialectOptions: {
            ssl: {
              require: true,
              rejectUnauthorized: false
            }
          }
        }
      );
      this.db = sequelize;
    } catch (err) {
      console.log('err-->', err);
      process.exit();
    }
  }
}
