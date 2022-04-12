import DB from '../util/db';
const Sequelize = require('sequelize');
const sequelize = new DB();

const UserSchema = sequelize.db.define(
  'users',
  {
    id: {
      type: Sequelize.INTEGER,
      primaryKey: true,
      autoIncrement: true // Automatically gets converted to SERIAL for postgres
    },
    first_name: {
      type: Sequelize.STRING
    },
    last_name: {
      type: Sequelize.STRING
    },
    image: {
      type: Sequelize.STRING
    },
    username: {
      type: Sequelize.STRING
    },
    contact_no: {
      type: Sequelize.STRING
    },
    email: {
      type: Sequelize.STRING
    },
    password: {
      type: Sequelize.STRING
    },
    role: {
      type: Sequelize.STRING,
      defaultValue: 'user'
    },
    status: {
      type: Sequelize.INTEGER,
      defaultValue: 1
    }
  },
  {
    tableName: 'users',
    createdAt: 'created_at',
    updatedAt: 'updated_at'
  }
);
sequelize.db
  .sync({ force: false })
  .then(function(data) {})
  .then(function(jane) {});

export default UserSchema;
export { sequelize };
