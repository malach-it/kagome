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
  const response = http.post(
    tokenTarget,
    {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "code_chain",
      id_token: validIdToken(),
    },
    formHeaders(),
  );
  const { wrappedChecks } = runChecks(response, authorizationCodeChecks());

  check(response, wrappedChecks);
}
