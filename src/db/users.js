const users = {
  registerUser: `INSERT INTO users (id, name, email) VALUES ($1, $2, $3) RETURNING id`,
  getUser: `SELECT * from users WHERE name = $1`,
  updateUser: `UPDATE users SET registered = $2, cred_format = $3, public_key = $4, cred_id = $5 WHERE email = $1`
};

module.exports = users;
