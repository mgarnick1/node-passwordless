const base64url = require("base64url");
const crypto = require("crypto");

const generateBase64UrlBuffer = (len = 32) => {
  const buffer = crypto.randomBytes(len);
  const arrayBuffer = base64url(buffer);
  return arrayBuffer;
};

const generateServerMakeCredRequest = (email, name, id) => {
  return {
    rp: {
      name: "WebAuth Test",
    },
    challenge: generateBase64UrlBuffer(),
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
      requireResidentKey: false,
      userVerification: "preferred",
    },
    extensions: {
      credProps: true,
    },
    timeout: 60000,
    attestation: "direct",
  };
};

module.exports = {
  generateBase64UrlBuffer,
  generateServerMakeCredRequest,
};
