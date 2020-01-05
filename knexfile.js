require('dotenv').config();

module.exports = {
  development: {
    client: 'pg',
    connection: {
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      port: process.env.DB_PORT,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      ssl: true,
    },
    searchPath: ['knex', 'public'],
  },
  staging: {
    client: 'pg',
    connection: {
      host: process.env.HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DATABASE,
      ssl: true,
    },
    searchPath: ['knex', 'public'],
  },
  production: {
    client: 'pg',
    connection: {
      host: process.env.HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DATABASE,
      ssl: true,
    },
    searchPath: ['knex', 'public'],
  }
}