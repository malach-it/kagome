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
export const credentialIdentifier =
  __ENV.KAGOME_CREDENTIAL_IDENTIFIER || "UniversityDegreeCredential";

const credentialProofPublicJwk = {
  kty: "EC",
  crv: "P-256",
  x: "2OOMuJdc5XAbumGYaUtM3ngfBVFhqjeqb0fJ_N3Y7UI",
  y: "Yp8TpPyvA3t9jF01vn7Z6SXYjpKkZOrO1Gg7CkxnMF8",
};
const credentialProofPrivateJwk = {
  ...credentialProofPublicJwk,
  d: "9SWS4Y9IULSULCeaXPaFWOCkkYV_k1RW1NCRhdqo8NE",
  key_ops: ["sign"],
  ext: true,
};

const noRedirects = { redirects: 0 };
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

  return http.get(target, {
    ...noRedirects,
    headers: { Host: publicHost },
    tags: { name: "GET /authorize" },
  });
}

export async function issueCredential(proofFactory = defaultCredentialProof) {
  const authorizeResponse = authorize(preAuthorizedCodeResponse);
  const authorizeLocation = credentialOfferLocation(authorizeResponse);
  const offer = jsonParameter(authorizeLocation, "credential_offer");
  const code =
    offer?.grants?.[preAuthorizedCodeGrant]?.["pre-authorized_code"];

  const offerDelivered =
    (authorizeResponse.status === 302 &&
      authorizeLocation.startsWith(redirectUri)) ||
    (authorizeResponse.status === 200 && authorizeLocation.length > 0);

  check(authorizeResponse, {
    "credential offer is delivered to the client": () => offerDelivered,
    "credential offer contains a pre-authorized code": () =>
      typeof code === "string" && code.length > 0,
  });
  if (
    !offerDelivered ||
    typeof code !== "string" ||
    code.length === 0
  ) {
    const authorizeBody = json(authorizeResponse);
    throw new Error(
      `credential authorization failed: HTTP ${authorizeResponse.status} ${authorizeBody.error_description || authorizeLocation || String(authorizeResponse.body || "").slice(0, 200)}`,
    );
  }

  const tokenResponse = http.post(
    `${serverTarget}/token`,
    {
      grant_type: preAuthorizedCodeGrant,
      "pre-authorized_code": code,
    },
    formOptions("POST /token"),
  );
  const tokenBody = json(tokenResponse);
  const token = tokenBody.access_token;
  const cNonce = tokenBody.c_nonce;

  check(tokenResponse, {
    "pre-authorized code exchange succeeds": (response) =>
      response.status === 200,
    "credential access token is present": () =>
      typeof token === "string" && token.length > 0,
    "credential nonce is present": () =>
      typeof cNonce === "string" && cNonce.length > 0,
  });
  if (
    tokenResponse.status !== 200 ||
    typeof token !== "string" ||
    token.length === 0 ||
    typeof cNonce !== "string" ||
    cNonce.length === 0
  ) {
    throw new Error(
      `pre-authorized code exchange failed: HTTP ${tokenResponse.status} ${tokenBody.error_description || tokenResponse.body}`,
    );
  }

  const credentialRequest = {
    credential_identifier: credentialIdentifier,
    proof: {
      proof_type: "jwt",
      jwt: await proofFactory(cNonce),
    },
  };
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
  if (
    credentialResponse.status !== 200 ||
    json(credentialResponse).format !== "jwt_vc" ||
    !isJwt(credential)
  ) {
    const credentialBody = json(credentialResponse);
    throw new Error(
      `credential issuance failed: HTTP ${credentialResponse.status} ${credentialBody.error_description || credentialResponse.body}`,
    );
  }

  return credential;
}

export function credentialOfferLocation(response) {
  const redirect = location(response);
  if (redirect) {
    return redirect;
  }

  if (response.status !== 200 || typeof response.body !== "string") {
    return "";
  }

  const match = response.body.match(/data-deep-link="([^"]+)"/);
  return match ? match[1].replace(/&amp;/g, "&") : "";
}

async function defaultCredentialProof(cNonce) {
  const holder = `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${jwkThumbprint(credentialProofPublicJwk)}`;
  return signEs256(
    { alg: "ES256", typ: "openid4vci-proof+jwt", jwk: credentialProofPublicJwk },
    {
      iss: holder,
      sub: holder,
      aud: issuer,
      iat: Math.floor(Date.now() / 1000),
      nonce: cNonce,
    },
    credentialProofPrivateJwk,
  );
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
