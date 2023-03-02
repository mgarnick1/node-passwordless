const { pool } = require("../pool");

const users = require("./db/users");
const utils = require("./utils");

const registerUser = async (req, res) => {
  const { name, email } = req.body;
  const exists = await pool.query(users.getUser, [name]);
  if (exists?.rows?.length) {
    return res.status(201).send("User exists");
  }
  const id = utils.generateBase64UrlBuffer();
  try {
    const response = await pool.query(users.registerUser, [
      id,
      name,
      email
    ]);
    const makeCredChallenge = utils.generateServerMakeCredRequest(
      email,
      name,
      id
    );
    return res.status(200).json(makeCredChallenge);
  } catch (e) {
    throw e;
  }
};

module.exports = {
  registerUser,
};
