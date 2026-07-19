require('dotenv').config();
const { migrate, pool } = require('../db');

migrate()
  .then(() => console.log('Database migration complete.'))
  .then(() => pool.end())
  .catch(error => {
    console.error(error);
    process.exitCode = 1;
  });

