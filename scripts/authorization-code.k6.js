import { check } from "k6";
import http from "k6/http";
import {
  clientSecret,
  formHeaders,
  idTokenClientId,
  options,
  runChecks,
  tokenChecks,
  tokenTarget,
  validHybridGrant,
} from "./token-helpers.js";

export { options };

export default async function () {
  const grant = validHybridGrant();
  const response = http.post(
    tokenTarget,
    {
      client_id: idTokenClientId,
      client_secret: clientSecret,
      grant_type: "authorization_code",
      code: grant.authorizationCode,
      code_verifier: grant.codeVerifier,
    },
    formHeaders(),
  );
  const { wrappedChecks } = runChecks(
    response,
    tokenChecks({
      token_type: "bearer",
      expires_in: 3600,
    }),
  );

  check(response, wrappedChecks);
}
