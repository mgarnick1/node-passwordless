const base64url = require("base64url");
const crypto = require("crypto");
const iso = require("iso-3166-1");
const { Certificate } = require("@fidm/x509");
const cbor = require("cbor");

const generateBase64UrlBuffer = (len = 32) => {
  const buffer = crypto.randomBytes(len);
  const arrayBuffer = base64url(buffer);
  return arrayBuffer;
};

const generateServerMakeCredRequest = (email, name, id) => {
  return {
    rp: {
      name: "WebAuth Test",
      id: "localhost",
    },
    challenge: generateBase64UrlBuffer(32),
    user: {
      id,
      name: email,
      displayName: name,
    },
    pubKeyCredParams: [
      {
        type: "public-key",
        alg: -7, // "ES256" as registered in the IANA COSE Algorithms registry
      },
      {
        type: "public-key",
        alg: -257, // Value registered by this specification for "RS256"
      },
    ],
    authenticatorSelection: {
      residentKey: "preferred",
      requireResidentKey: true,
      authenticatorAttachment: "platform", 
      userVerification: "required",
    },
    timeout: 60000,
    attestation: "direct",
  };
};

const U2F_USER_PRESENTED = 0x01;

// * Takes signature, data and PEM public key and tries to verify signature
const verifySignature = (signature, data, publicKey) => {
  return crypto
    .createVerify("SHA256")
    .update(data)
    .verify(publicKey, signature);
};

// Generates getAssertion request
const generateServerGetAssertion = (authenticators) => {
  const allowCredentials = [];
  for (const auth of authenticators) {
    allowCredentials.push({
      type: "public-key",
      id: auth.credId,
      transports: ["usb", "nfc", "ble", "internal"],
    });
  }
  return {
    challenge: generateBase64UrlBuffer(32),
    allowCredentials: allowCredentials,
    userVerification: "preferred",
    rpId: "localhost",
    timeout: 60000,
  };
};

//Returns SHA-256 digest of the given data. takes a Buffer
const hash = (data) => {
  return crypto.createHash("SHA256").update(data).digest();
};

// Takes COSE encoded public key and converts it to RAW PKCS ECDHA key, COSE Public Key is Buffer Return Raw PKS encoded public key
const COSEECDHAtoPKCS = (COSEPublicKey) => {
  const coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
  const tag = Buffer.from([0x04]);
  const x = coseStruct.get(-2);
  const y = coseStruct.get(-3);

  return Buffer.concat([tag, x, y]);
};

/// Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
const ASN1toPEM = (pkBuffer) => {
  if (!Buffer.isBuffer(pkBuffer)) {
    throw new Error("ASN1toPEM: pkBuffer must be a buffer");
  }
  let type;
  if (pkBuffer.length === 65 && pkBuffer[0] === 0x04) {
    pkBuffer = Buffer.concat([
      new Buffer.from(
        "3059301306072a8648ce3d020106082a8648ce3d030107034200",
        "hex"
      ),
      pkBuffer,
    ]);

    type = "PUBLIC KEY";
  } else {
    type = "CERTIFICATE";
  }

  const base64Cert = pkBuffer.toString("base64");
  let PEMKey = "";
  for (let i = 0; i < Math.ceil(base64Cert.length / 64); i++) {
    let start = 64 * i;
    PEMKey += base64Cert.substr(start, 64) + "\n";
  }

  PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;

  return PEMKey;
};

// Parses authenticatorData buffer. Takes a Buffer returns a Object

const parseMakeCredAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);

  let flagsBuf = buffer.slice(0, 1);
  buffer = buffer.slice(1);

  let flags = flagsBuf[0];

  let counterBuf = buffer.slice(0, 4);
  buffer = buffer.slice(4);

  let counter = counterBuf.readUInt32BE(0);
  let aaguid = buffer.slice(0, 16);
  buffer = buffer.slice(16);

  let credIdLenBuf = buffer.slice(0, 2);
  buffer = buffer.slice(2);

  let credIdLen = credIdLenBuf.readUInt16BE(0);
  let credId = buffer.slice(0, credIdLen);
  buffer = buffer.slice(credIdLen);
  let COSEPublicKey = buffer;

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credId,
    COSEPublicKey,
  };
};

const checkAAGuidValid = (aaguid_ext, authrDataStruct) => {
  if (aaguid_ext !== null) {
    if (authrDataStruct && authrDataStruct.aaguid) {
      return (
        !aaguid_ext.critical &&
        aaguid_ext.value.slice(2).equals(authrDataStruct.aaguid)
      );
    }
    return false;
  }
  return true;
};

const verifyAuthenticatorAttestationResponse = (response) => {
  const attestationBuffer = base64url.toBuffer(response.attestationObject);
  let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];
  let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);
  let clientDataHash = hash(base64url.toBuffer(response.clientDataJSON));
  let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);
  let signature = ctapMakeCredResp.attStmt.sig;

  let res = { verified: false };

  if (ctapMakeCredResp.fmt === "fido-u2f") {
    if (!(authDataStruct.flags && U2F_USER_PRESENTED)) {
      throw new Error("User was not present during authentication");
    }

    let reservedByte = Buffer.from([0x00]);

    let signatureBase = Buffer.concat([
      reservedByte,
      authrDataStruct.rpIdHash,
      clientDataHash,
      authrDataStruct.credId,
      publicKey,
    ]);

    let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt?.x5c[0]);

    res.verified = verifySignature(signature, signatureBase, PEMCertificate);

    if (res.verified) {
      res.authrInfo = {
        fmt: "fido-u2f",
        publicKey: base64url.encode(publicKey),
        counter: authrDataStruct.counter,
        credId: base64url.encode(authrDataStruct.credId),
      };
    }
  } else if (
    ctapMakeCredResp.fmt === "packed" &&
    "x5c" in ctapMakeCredResp.attStmt
  ) {
    // let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

    if (!(authDataStruct.flags && U2F_USER_PRESENTED)) {
      throw new Error("User was not present during authentication");
    }

    // let clientDataHash = hash(base64url.toBuffer(response.clientDataJSON));

    // let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);

    let signatureBase = Buffer.concat([
      ctapMakeCredResp.authData,
      clientDataHash,
    ]);

    let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt?.x5c[0]);

    // let signature = ctapMakeCredResp.attStmt.sig;

    let pem = Certificate.fromPEM(PEMCertificate);

    let aaguid_ext = pem.getExtension("1.3.6.1.4.1.45724.1.1.4");

    let aaguid_valid = checkAAGuidValid(aaguid_ext, authrDataStruct);

    res.verified =
      verifySignature(signature, signatureBase, PEMCertificate) &&
      pem.version === 3 &&
      typeof iso.whereAlpha2(pem.subject.countryName) !== "undefined" &&
      pem.subject.organizationName &&
      pem.subject.organizationalUnitName === "Authenticator Attestation" &&
      pem.subject.commonName &&
      !pem.extensions.isCA &&
      aaguid_valid;

    if (res.verified) {
      res.authrInfo = {
        fmt: "fido-u2f",
        publicKey: base64url.encode(publicKey),
        counter: authrDataStruct.counter,
        credId: base64url.encode(authrDataStruct.credId),
      };
    }
  } else if (ctapMakeCredResp.fmt === "packed") {
    // let clientDataHash = hash(base64url.toBuffer(response.clientDataJSON));

    const signatureBase = Buffer.concat([
      ctapMakeCredResp.authData,
      clientDataHash,
    ]);

    // let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);

    // let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey);

    const PEMCertificate = ASN1toPEM(publicKey);

    const {
      attStmt: { sig: signature, alg },
    } = ctapMakeCredResp;

    res.authrInfo = {
      fmt: "fido-u2f",
      publicKey: base64url.encode(publicKey),
      counter: authrDataStruct.counter,
      credId: base64url.encode(authrDataStruct.credId),
    };

    res.verified =
      verifySignature(signature, signatureBase, PEMCertificate) && alg === -7;
  } else if (ctapMakeCredResp.fmt === "none") {
    res.verified =
      this.config.attestation ==
      Dictionaries.AttestationConveyancePreference.NONE;
  } else {
    throw new Error("Unsupported attestation format! " + ctapMakeCredResp.fmt);
  }
  return res;
};

const findAuthr = (credId, authenticators) => {
  for (const authr of authenticators) {
    if (authr.credId === credId) {
      return authr;
    }
  }
  throw new Error(`Unknown authenticator with credId ${credId}`);
};


const findChallenge = (clientChallenge, sessionStore) => {
  let challengeValue = "";
  let userName = "";
  for (const key in sessionStore) {
    const session = sessionStore[key];
    if (session.includes("challenge")) {
      const json = JSON.parse(session);
      let jsonChallenge = json.challenge.replaceAll("-", "A");
      jsonChallenge = jsonChallenge.replaceAll("_", "A");
      if (jsonChallenge == clientChallenge) {
        challengeValue = jsonChallenge;
        userName = json.username;
      }
    }
  }
  return { challenge: challengeValue, username: userName };
};

/// Parses AuthenticatorData from GetAssertion response
const parseGetAssertAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);

  let flagsBuf = buffer.slice(0, 1);
  buffer = buffer.slice(1);

  let flags = flagsBuf[0];

  let counterBuf = buffer.slice(0, 4);
  buffer = buffer.slice(4);

  let counter = counterBuf.readUInt32BE(0);

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
  };
};

const verifyAuthenticatorAssertionResponse = (id, response, authenticators) => {
  let authr = findAuthr(id, authenticators);
  let authenticatorData = base64url.toBuffer(response.authenticatorData);

  let res = { verified: false };

  if (authr.fmt === "fido-u2f") {
    let authDataStruct = parseGetAssertAuthData(authenticatorData);

    if (!(authDataStruct.flags && U2F_USER_PRESENTED)) {
      throw new Error("User was not present during authentication");
    }

    let clientDataHash = hash(base64url.toBuffer(response.clientDataJSON));

    let signatureBase = Buffer.concat([
      authDataStruct.rpIdHash,
      authDataStruct.flagsBuf,
      authDataStruct.counterBuf,
      clientDataHash,
    ]);

    let publicKey = ASN1toPEM(base64url.toBuffer(authr.publicKey));

    let signature = base64url.toBuffer(response.signature);

    res.verified = verifySignature(signature, signatureBase, publicKey);

    if (res.verified) {
      if (res.counter <= authr.counter) {
        throw new Error("Authr counter did not increase!");
      }
      authr.counter = authDataStruct.counter;
    }
  }

  return res;
};

module.exports = {
  generateBase64UrlBuffer,
  generateServerMakeCredRequest,
  verifyAuthenticatorAttestationResponse,
  U2F_USER_PRESENTED,
  verifySignature,
  generateServerGetAssertion,
  hash,
  COSEECDHAtoPKCS,
  ASN1toPEM,
  findChallenge,
  findAuthr,
  parseMakeCredAuthData,
  parseGetAssertAuthData,
  verifyAuthenticatorAssertionResponse,
};
