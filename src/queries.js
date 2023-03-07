const { pool } = require("../pool");

const users = require("./db/users");
const utils = require("./utils");
const base64url = require("base64url");

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
    return res.status(200).json(makeCredChallenge);
  } catch (e) {
    throw e;
  }
};

const finishRegister = async (req, res) => {
  const { id, rawId, response, type } = req.body;
  let result;

  if (type !== "public-key") {
    res.badRequest({
      status: "error",
      message: "Registration failed! type is not public-key",
    });
    return;
  }

  const clientData = JSON.parse(base64url.decode(response.clientDataJSON));
  if (clientData.challenge !== req.session.challenge) {
    res.badRequest({
      status: "error",
      message: "Registration failed! Challenges do not match",
    });
    return;
  }

  if (clientData.origin !== "http://localhost:2001") {
    res.badRequest({
      status: "error",
      message: "Registration failed! Origins do not match",
    });
    return;
  }

  if (response.attestationObject !== undefined) {
    // This is a create credential request
    result = utils.verifyAuthenticatorAttestationResponse(response);

    if (result.verified) {
      await pool.updateUser(
        req.session.username,
        true,
        result.authrInfo.fmt,
        result.authrInfo.publicKey,
        result.authrInfo.credid
      );
    }
  } else {
    res.badRequest("Cannot determine the type of response");
    return;
  }

  if (result.verified) {
    req.session.loggedIn = true;
    res.send("Registration successfull");
    return;
  } else {
    res.badRequest("Cannot authenticate signature");
    return;
  }
};

module.exports = {
  registerUser,
  finishRegister,
};
