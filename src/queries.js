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
  const sessionData = utils.findChallenge(clientData.challenge, req.sessionStore.sessions);
  req.session.challenge = sessionData.challenge;
  req.session.username = sessionData.username;
  if (clientData.challenge !== req.session.challenge) {
    console.log(clientData.challenge, req.session.challenge);
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
    res.send({message: "Registration successfull", registered: true});
    return;
  } else {
    res.status(500).send("Cannot authenticate signature");
    return;
  }
};

module.exports = {
  registerUser,
  finishRegister,
};
