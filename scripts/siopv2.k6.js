import { check } from "k6";
import http from "k6/http";
import {
  callbackTarget,
  clientId,
  formOptions,
  jwkThumbprint,
  location,
  options,
  parameters,
  query,
  redirectOptions,
  redirectUri,
  serverTarget,
  signEs256,
} from "./flow-helpers.js";

export { options };

const publicJwk = {
  kty: "EC",
  crv: "P-256",
  x: "2OOMuJdc5XAbumGYaUtM3ngfBVFhqjeqb0fJ_N3Y7UI",
  y: "Yp8TpPyvA3t9jF01vn7Z6SXYjpKkZOrO1Gg7CkxnMF8",
};
const privateJwk = {
  ...publicJwk,
  d: "9SWS4Y9IULSULCeaXPaFWOCkkYV_k1RW1NCRhdqo8NE",
  key_ops: ["sign"],
  ext: true,
};
const subject = `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${jwkThumbprint(publicJwk)}`;

export default async function () {
  const requestResponse = http.get(
    `${serverTarget}/siopv2-request?${query({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      state: "k6-state",
    })}`,
    redirectOptions("GET /siopv2-request"),
  );
  const walletRequest = parameters(location(requestResponse));
  const now = Math.floor(Date.now() / 1000);
  const idToken = await signEs256(
    { alg: "ES256", typ: "JWT", jwk: publicJwk },
    {
      iss: subject,
      sub: subject,
      sub_jwk: publicJwk,
      aud: walletRequest.redirect_uri,
      nonce: walletRequest.nonce,
      iat: now,
      exp: now + 300,
    },
    privateJwk,
  );
  const response = http.post(
    callbackTarget(walletRequest.redirect_uri),
    { id_token: idToken },
    {
      ...formOptions("POST /siopv2-response"),
      redirects: 0,
    },
  );
  const target = location(response);
  const result = parameters(target);

  check(requestResponse, {
    "SIOPv2 request redirects to a wallet": (request) =>
      request.status === 302 &&
      walletRequest.response_type === "id_token" &&
      typeof walletRequest.nonce === "string",
  });
  check(response, {
    "SIOPv2 response redirects to the client": (result) =>
      result.status === 302 && target.startsWith(`${redirectUri}?`),
    "SIOPv2 response returns an authorization code": () =>
      typeof result.code === "string" && result.code.length > 0,
  });
}
