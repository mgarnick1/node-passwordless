const users = {
  registerUser: `INSERT INTO users (id, name, email) VALUES ($1, $2, $3) RETURNING id`,
  getUser: `SELECT * from users WHERE name = $1`,
};

module.exports = users;
