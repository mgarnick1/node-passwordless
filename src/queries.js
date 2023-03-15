const { pool } = require("../pool");
const jwt = require("jsonwebtoken");

const users = require("./db/users");
const utils = require("./utils");
const base64url = require("base64url");
const axios = require("axios");

const registerUser = async (req, res) => {
  const { name, email } = req.body;
  const exists = await pool.query(users.getUser, [name]);
  if (exists?.rows?.length) {
    return res.status(201).send("User exists");
  }
  const id = utils.generateBase64UrlBuffer();
  try {
    const response = await pool.query(users.registerUser, [id, name, email]);
    const makeCredChallenge = utils.generateServerMakeCredRequest(
      email,
      name,
      id
    );
    req.session.challenge = makeCredChallenge.challenge;
    req.session.username = email;
    req.session.save();
    return res.status(200).json(makeCredChallenge);
  } catch (e) {
    throw e;
  }
};

const finishRegister = async (req, res) => {
  const { id, rawId, response, type } = req.body;
  let result;

  if (type !== "public-key") {
    res.status(500).json({
      status: "error",
      message: "Registration failed! type is not public-key",
    });
    return;
  }

  const clientData = JSON.parse(base64url.decode(response.clientDataJSON));
  const sessionData = utils.findChallenge(
    clientData.challenge,
    req.sessionStore.sessions
  );
  req.session.challenge = sessionData.challenge;
  req.session.username = sessionData.username;
  if (clientData.challenge !== req.session.challenge) {
    res.status(500).send({
      status: "error",
      message: "Registration failed! Challenges do not match",
    });
    return;
  }

  if (clientData.origin !== "http://localhost:2001") {
    res.status(500).send({
      status: "error",
      message: "Registration failed! Origins do not match",
    });
    return;
  }

  if (response.attestationObject !== undefined) {
    // This is a create credential request
    result = utils.verifyAuthenticatorAttestationResponse(response);

    if (result.verified) {
      await pool.query(users.updateUser, [
        req.session.username,
        1,
        result.authrInfo.fmt,
        result.authrInfo.publicKey,
        result.authrInfo.credId,
      ]);
    }
  } else {
    res.status(500).json("Cannot determine the type of response");
    return;
  }

  if (result.verified) {
    req.session.loggedIn = true;
    res.send({ message: "Registration successfull", registered: true });
    return;
  } else {
    res.status(500).send("Cannot authenticate signature");
    return;
  }
};

const login = async (req, res) => {
  const { email } = req.body;
  const user = await pool.query(users.getUserByEmail, [email]);
  if (!user.rows?.length || !user.rows[0]?.registered) {
    res.status(400).send({
      message: `User: ${email} does not exist`,
    });
    return;
  }
  const userObj = user.rows[0];
  const authenticator = {
    fmt: userObj.fmt,
    publicKey: userObj.public_key,
    credId: userObj.cred_id,
  };

  const getAssertion = utils.generateServerGetAssertion([authenticator]);
  req.session.challenge = getAssertion.challenge;
  req.session.username = email;

  res.status(200).send(getAssertion);
};

const verify = async (req, res) => {
  const { id, response, type } = req.body;
  let result = {};

  if (type !== "public-key") {
    res.status(500).send({
      message: `Type is not public-key`,
    });
    return;
  }
  const clientData = JSON.parse(base64url.decode(response.clientDataJSON));
  const sessionData = utils.findChallenge(
    clientData.challenge,
    req.sessionStore.sessions
  );
  req.session.challenge = sessionData.challenge;
  req.session.username = sessionData.username;
  if (clientData.challenge !== req.session.challenge) {
    res.status(500).send({
      status: "error",
      message: "Challenges do not match",
    });
    return;
  }
  if (clientData.origin !== "http://localhost:2001") {
    res.status(500).send({
      status: "error",
      message: "Origins do not match",
    });
    return;
  }
  let user = undefined;
  let userObj = {};
  if (response.authenticatorData !== undefined) {
    user = await pool.query(users.getUserByCredId, [id]);
    if (!user.rows?.length || !user.rows[0].registered) {
      res.status(400).send({
        message: `User: ${email} does not exist`,
      });
      return;
    }
    userObj = user.rows[0];

    const authenticator = {
      fmt: userObj.fmt,
      publicKey: userObj.public_key,
      credId: userObj.cred_id,
    };
    result = utils.verifyAuthenticatorAssertionResponse(id, response, [
      authenticator,
    ]);
  } else {
    res.status(500).send({
      status: "error",
      message: "Cannot determine the type of response",
    });
  }

  if (result.verified) {
    const token = jwt.sign(
      {
        id,
        name: userObj.name,
        email: userObj.email,
        exp: Math.floor(Date.now() / 1000) + 60 * 60,
      },
      process.env.JWTSECRET
    );
    req.session.loggedIn = true;
    res.send({
      verification: true,
      token,
      user: { email: userObj.email, name: userObj.name, registered: true },
    });
  } else {
    res.status(500).send({
      status: "error",
      message: "Cannot authenticate signature",
      verification: false,
    });
  }
};

const logout = async (req, res) => {
  req.session.destroy();
  res.send({ message: "User Logged out" });
};

const getQuotes = async (req, res) => {
  const ApiKey = process.env.APININJA_APIKEY;
  try {
    const response = await axios.get(
      `https://api.api-ninjas.com/v1/quotes?category=funny`,
      {
        headers: {
          "X-Api-Key": ApiKey,
          "Content-Type": "application/json",
        },
      }
    );
    if (response.data && response.data) {
      res.send({
        quote: response.data[0],
      });
    }
  } catch (e) {}
};

module.exports = {
  registerUser,
  finishRegister,
  login,
  verify,
  logout,
  getQuotes,
};
