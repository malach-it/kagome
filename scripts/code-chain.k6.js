import { check } from "k6";
import http from "k6/http";
import {
  authorizationCodeChecks,
  clientId,
  clientSecret,
  formHeaders,
  options,
  runChecks,
  tokenTarget,
  validIdToken,
} from "./token-helpers.js";

export { options };

export default function () {
  const codeCount = randomCodeCount();
  let authorizationCode;

  check({ codeCount }, {
    "code chain length is between 0 and 10": ({ codeCount }) =>
      codeCount >= 0 && codeCount <= 10,
  });

  for (let index = 0; index < codeCount; index += 1) {
    const response = http.post(
      tokenTarget,
      codeChainRequestBody(authorizationCode),
      formHeaders(),
    );
    const { payload, wrappedChecks } = runChecks(
      response,
      authorizationCodeChecks(),
    );

    check(response, wrappedChecks);
    authorizationCode = payload.authorization_code;
  }
}

function randomCodeCount() {
  return Math.floor(Math.random() * 11);
}

function codeChainRequestBody(authorizationCode) {
  const body = {
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "code_chain",
    id_token: validIdToken(),
  };

  if (authorizationCode !== undefined) {
    body.authorization_code = authorizationCode;
  }

  return body;
}
