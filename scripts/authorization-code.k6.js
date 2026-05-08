import { check } from "k6";
import http from "k6/http";
import {
  clientId,
  clientSecret,
  formHeaders,
  options,
  runChecks,
  tokenChecks,
  tokenTarget,
  validIdToken,
} from "./token-helpers.js";

export { options };

export default function () {
  const codeChainResponse = http.post(
    tokenTarget,
    {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "code_chain",
      id_token: validIdToken(),
    },
    formHeaders(),
  );
  const authorizationCode = codeChainResponse.json().authorization_code;
  const response = http.post(
    tokenTarget,
    {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "authorization_code",
      authorization_code: authorizationCode,
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
