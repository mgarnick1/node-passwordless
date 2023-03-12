const users = {
  registerUser: `INSERT INTO users (id, name, email) VALUES ($1, $2, $3) RETURNING id`,
  getUser: `SELECT * from users WHERE name = $1`,
  getUserByEmail: `SELECT * from users where email = $1`,
  updateUser: `UPDATE users SET registered = $2, fmt = $3, public_key = $4, cred_id = $5 WHERE email = $1`,
  getUserByCredId: `SELECT * from users WHERE cred_id = $1`
};

module.exports = users;
