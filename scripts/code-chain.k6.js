import { check } from "k6";
import http from "k6/http";
import {
  authorizationCodeChecks,
  formHeaders,
  idTokenClientId,
  options,
  runChecks,
  tokenTarget,
  validIdToken,
} from "./token-helpers.js";

export { options };

export default async function () {
  const codeCount = randomCodeCount();
  let authorizationCode;

  check({ codeCount }, {
    "code chain length is between 0 and 10": ({ codeCount }) =>
      codeCount >= 0 && codeCount <= 8,
  });

  for (let index = 0; index < codeCount; index += 1) {
    const response = http.post(
      tokenTarget,
      await codeChainRequestBody(authorizationCode),
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
  return Math.floor(Math.random() * 7);
}

async function codeChainRequestBody(authorizationCode) {
  const body = {
    client_id: idTokenClientId,
    grant_type: "code_chain",
    id_token: await validIdToken(),
  };

  if (authorizationCode !== undefined) {
    body.authorization_code = authorizationCode;
  }

  return body;
}
