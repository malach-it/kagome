import { check } from "k6";
import k6Crypto from "k6/crypto";
import encoding from "k6/encoding";
import http from "k6/http";

export const options = {
  vus: Number(__ENV.K6_VUS || "4"),
  duration: __ENV.K6_DURATION || "30s",
  thresholds: {
    checks: ["rate>0.99"],
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500"],
  },
};

export const serverTarget =
  __ENV.KAGOME_SERVER_TARGET || "http://kagome:4000";
export const clientId = __ENV.KAGOME_CLIENT_ID || "client_id";
export const clientSecret = __ENV.KAGOME_CLIENT_SECRET || "client_secret";
export const redirectUri =
  __ENV.KAGOME_REDIRECT_URI || "https://client.example.com/callback";
export const username = __ENV.KAGOME_USERNAME || "username";
export const password = __ENV.KAGOME_PASSWORD || "password";
export const issuer = __ENV.KAGOME_ISSUER || "http://localhost:4000";
export const publicHost = __ENV.KAGOME_PUBLIC_HOST || "localhost:4000";
export const authorizeClientId =
  __ENV.KAGOME_AUTHORIZE_CLIENT_ID ||
  `${username}@${publicHost}`;

export const preAuthorizedCodeGrant =
  "urn:ietf:params:oauth:grant-type:pre-authorized_code";
export const preAuthorizedCodeResponse =
  "urn:ietf:params:oauth:response-type:pre-authorized_code";
export const credentialIdentifier = "UniversityDegreeCredential";

const noRedirects = { redirects: 0 };
const formNoRedirects = {
  headers: { "content-type": "application/x-www-form-urlencoded" },
  redirects: 0,
};

export function formOptions(name) {
  return {
    headers: { "content-type": "application/x-www-form-urlencoded" },
    ...(name === undefined ? {} : { tags: { name } }),
  };
}

export function redirectOptions(name) {
  return {
    ...noRedirects,
    ...(name === undefined ? {} : { tags: { name } }),
  };
}

export function authorize(responseType) {
  const target = `${serverTarget}/authorize?${query({
      response_type: responseType,
      client_id: authorizeClientId,
      redirect_uri: redirectUri,
      state: "k6-state",
    })}`;

  if ((__ENV.KAGOME_AUTHORIZE_METHOD || "GET").toUpperCase() === "POST") {
    return http.post(target, { username, password }, {
      ...formNoRedirects,
      headers: {
        ...formNoRedirects.headers,
        Host: publicHost,
      },
      tags: { name: "POST /authorize" },
    });
  }

  return http.get(target, {
    ...noRedirects,
    headers: { Host: publicHost },
    tags: { name: "GET /authorize" },
  });
}

export function issueCredential(proof) {
  const authorizeResponse = authorize(preAuthorizedCodeResponse);
  const authorizeLocation = location(authorizeResponse);
  const offer = jsonParameter(authorizeLocation, "credential_offer");
  const code =
    offer?.grants?.[preAuthorizedCodeGrant]?.["pre-authorized_code"];

  check(authorizeResponse, {
    "credential offer redirects to the client": (response) =>
      response.status === 302 && authorizeLocation.startsWith(redirectUri),
    "credential offer contains a pre-authorized code": () =>
      typeof code === "string" && code.length > 0,
  });

  const tokenResponse = http.post(
    `${serverTarget}/token`,
    {
      grant_type: preAuthorizedCodeGrant,
      "pre-authorized_code": code,
      tx_code: __ENV.KAGOME_TX_CODE || "493536",
    },
    formOptions("POST /token"),
  );
  const token = json(tokenResponse).access_token;

  check(tokenResponse, {
    "pre-authorized code exchange succeeds": (response) =>
      response.status === 200,
    "credential access token is present": () =>
      typeof token === "string" && token.length > 0,
  });

  const credentialRequest = { credential_identifier: credentialIdentifier };
  if (proof !== undefined) {
    credentialRequest.proof = { proof_type: "jwt", jwt: proof };
  }
  const credentialResponse = http.post(
    `${serverTarget}/credential`,
    JSON.stringify(credentialRequest),
    {
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      tags: { name: "POST /credential" },
    },
  );
  const credential = json(credentialResponse).credential;

  check(credentialResponse, {
    "credential issuance succeeds": (response) => response.status === 200,
    "credential response uses jwt_vc": (response) =>
      json(response).format === "jwt_vc",
    "issued credential is a JWT": () => isJwt(credential),
  });

  return credential;
}

export function location(response) {
  return response.headers.Location || response.headers.location || "";
}

export function parameters(uri) {
  const queryOrFragment = uri.includes("?")
    ? uri.slice(uri.indexOf("?") + 1).split("#", 1)[0]
    : uri.includes("#")
      ? uri.slice(uri.indexOf("#") + 1)
      : "";

  return Object.fromEntries(
    queryOrFragment
      .split("&")
      .filter((entry) => entry.length > 0)
      .map((entry) => {
        const separator = entry.indexOf("=");
        const name = separator === -1 ? entry : entry.slice(0, separator);
        const value = separator === -1 ? "" : entry.slice(separator + 1);
        return [decode(name), decode(value)];
      }),
  );
}

export function callbackTarget(uri) {
  const path = uri.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]+/i, "");
  return `${serverTarget}${path.startsWith("/") ? path : `/${path}`}`;
}

export function query(values) {
  return Object.entries(values)
    .filter(([, value]) => value !== undefined)
    .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`)
    .join("&");
}

export function json(response) {
  try {
    return response.json();
  } catch (_error) {
    return {};
  }
}

export function isJwt(value) {
  return typeof value === "string" && value.split(".").length === 3;
}

export function jwtPayload(value) {
  if (!isJwt(value)) {
    return {};
  }
  try {
    return JSON.parse(encoding.b64decode(value.split(".")[1], "rawurl", "s"));
  } catch (_error) {
    return {};
  }
}

export async function signEs256(header, claims, privateJwk) {
  const key = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  return signJwt(
    header,
    claims,
    key,
    { name: "ECDSA", hash: "SHA-256" },
  );
}

export function jwkThumbprint(jwk) {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  return k6Crypto.sha256(canonical, "base64rawurl");
}

async function signJwt(header, claims, key, algorithm) {
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(claims)}`;
  const signature = await crypto.subtle.sign(
    algorithm,
    key,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${encoding.b64encode(signature, "rawurl")}`;
}

function base64UrlJson(value) {
  return encoding.b64encode(JSON.stringify(value), "rawurl");
}

function jsonParameter(uri, name) {
  const value = parameters(uri)[name];
  if (value === undefined) {
    return undefined;
  }
  try {
    return JSON.parse(value);
  } catch (_error) {
    return undefined;
  }
}

function decode(value) {
  return decodeURIComponent(value.replace(/\+/g, " "));
}
