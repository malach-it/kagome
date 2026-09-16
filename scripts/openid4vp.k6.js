import { check } from "k6";
import http from "k6/http";
import {
  callbackTarget,
  clientId,
  issuer,
  issueCredential,
  jwkThumbprint,
  jwtPayload,
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

export default async function () {
  const holder = `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${jwkThumbprint(publicJwk)}`;
  const now = Math.floor(Date.now() / 1000);
  const credential = await issueCredential(
    async (cNonce) =>
      await signEs256(
        { alg: "ES256", typ: "openid4vci-proof+jwt", jwk: publicJwk },
        { iss: holder, sub: holder, aud: issuer, iat: now, nonce: cNonce },
        privateJwk,
      ),
  );
  const requestResponse = http.get(
    `${serverTarget}/authorize?${query({
      response_type: "vp_token",
      client_id: clientId,
      redirect_uri: redirectUri,
      state: "k6-state",
    })}`,
    redirectOptions("GET /authorize"),
  );
  const walletRequest = parameters(location(requestResponse));
  const requestObject = jwtPayload(walletRequest.request);
  const vpToken = await signEs256(
    { alg: "ES256", typ: "JWT", jwk: publicJwk },
    {
      iss: holder,
      aud: walletRequest.client_id,
      nonce: requestObject.nonce,
      iat: now,
      nbf: now,
      exp: now + 300,
      vp: {
        type: ["VerifiablePresentation"],
        verifiableCredential: [credential],
      },
    },
    privateJwk,
  );
  const definition = requestObject.presentation_definition;
  const descriptorId = definition.input_descriptors[0].id;
  const submission = {
    id: "k6-presentation-submission",
    definition_id: definition.id,
    descriptor_map: [
      {
        id: descriptorId,
        format: "jwt_vp",
        path: "$",
        path_nested: {
          id: descriptorId,
          format: "jwt_vc",
          path: "$.vp.verifiableCredential[0]",
        },
      },
    ],
  };
  const response = http.post(
    callbackTarget(walletRequest.redirect_uri),
    {
      vp_token: vpToken,
      presentation_submission: JSON.stringify(submission),
    },
    {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      redirects: 0,
      tags: { name: "POST /presentation-response" },
    },
  );
  const target = location(response);
  const result = parameters(target);

  check(requestResponse, {
    "OpenID4VP request redirects to a wallet": (request) =>
      request.status === 302 &&
      walletRequest.response_type === "vp_token" &&
      typeof requestObject.nonce === "string",
  });
  check(response, {
    "OpenID4VP response redirects to the client": (result) =>
      result.status === 302 && target.startsWith(`${redirectUri}?`),
    "OpenID4VP response returns an authorization code": () =>
      typeof result.code === "string" && result.code.length > 0,
    "OpenID4VP response preserves client state": () => result.state === "k6-state",
  });
}
