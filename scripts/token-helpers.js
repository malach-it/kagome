import { signEs256 } from "./flow-helpers.js";

export const options = {
  vus: Number(__ENV.K6_VUS || "4"),
  duration: __ENV.K6_DURATION || "30s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500"],
  },
};

export const tokenTarget =
  __ENV.KAGOME_TOKEN_TARGET || "http://kagome:4000/token";

export const clientId = __ENV.KAGOME_CLIENT_ID || "client_id";
export const clientSecret = __ENV.KAGOME_CLIENT_SECRET || "client_secret";

export function formHeaders() {
  return {
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
  };
}

export function tokenChecks(expected) {
  return {
    "status is 200": (response) => response.status === 200,
    "token_type is bearer": (_response, payload) =>
      payload.token_type === expected.token_type,
    "access_token is present": (_response, payload) =>
      typeof payload.access_token === "string" && payload.access_token.length > 0,
    "expires_in is valid": (_response, payload) =>
      payload.expires_in === expected.expires_in,
    "authorization_code is omitted": (_response, payload) =>
      payload.authorization_code === undefined,
  };
}

export function authorizationCodeChecks() {
  return {
    "status is 200": (response) => response.status === 200,
    "authorization_code is present": (_response, payload) =>
      typeof payload.authorization_code === "string" &&
      payload.authorization_code.length > 0,
    "expires_in is valid": (_response, payload) => payload.expires_in === 600,
    "access_token is omitted": (_response, payload) =>
      payload.access_token === undefined,
  };
}

export function runChecks(response, checks) {
  const payload = response.json();
  const wrappedChecks = Object.fromEntries(
    Object.entries(checks).map(([name, assertion]) => [
      name,
      (response) => assertion(response, payload),
    ]),
  );

  return { payload, wrappedChecks };
}

const idTokenPublicJwk = {
  kty: "EC",
  crv: "P-256",
  x: "2OOMuJdc5XAbumGYaUtM3ngfBVFhqjeqb0fJ_N3Y7UI",
  y: "Yp8TpPyvA3t9jF01vn7Z6SXYjpKkZOrO1Gg7CkxnMF8",
};
const idTokenPrivateJwk = {
  ...idTokenPublicJwk,
  d: "9SWS4Y9IULSULCeaXPaFWOCkkYV_k1RW1NCRhdqo8NE",
  key_ops: ["sign"],
  ext: true,
};

export async function validIdToken() {
  const now = currentTimestamp();
  return signEs256(
    {
      alg: "ES256",
      typ: "JWT",
      jwk: idTokenPublicJwk,
    },
    {
      iat: now,
      exp: now + 3600,
      message: randomMessage(10, 200),
    },
    idTokenPrivateJwk,
  );
}

function randomMessage(minLength, maxLength) {
  const alphabet =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const length =
    minLength + Math.floor(Math.random() * (maxLength - minLength + 1));

  return Array.from({ length }, () =>
    alphabet.charAt(Math.floor(Math.random() * alphabet.length)),
  ).join("");
}

function currentTimestamp() {
  return Math.floor(Date.now() / 1000);
}
