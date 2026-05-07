import crypto from "k6/crypto";
import encoding from "k6/encoding";

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

export function validIdToken() {
  const now = currentTimestamp();
  return signJwt(
    {
      alg: "HS256",
      typ: "JWT",
      jwk: {
        kty: "oct",
        k: "c2VjcmV0",
        alg: "HS256",
      },
    },
    {
      iat: now,
      exp: now + 3600,
    },
    "secret",
    "sha256",
  );
}

export function validAuthorizationCode(idToken) {
  const now = currentTimestamp();
  return signJwt(
    {
      alg: "HS512",
      typ: "JWT",
    },
    {
      client_id: clientId,
      id_token: idToken,
      iat: now,
      exp: now + 600,
    },
    "static_authorization_code_secret",
    "sha512",
  );
}

function signJwt(header, payload, secret, algorithm) {
  const encodedHeader = base64UrlJson(header);
  const encodedPayload = base64UrlJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.hmac(
    algorithm,
    secret,
    signingInput,
    "base64rawurl",
  );

  return `${signingInput}.${signature}`;
}

function base64UrlJson(value) {
  return encoding.b64encode(JSON.stringify(value), "rawurl");
}

function currentTimestamp() {
  return Math.floor(Date.now() / 1000);
}
