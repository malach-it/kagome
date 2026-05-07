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
} from "./token-helpers.js";

export { options };

export default function () {
  const response = http.post(
    tokenTarget,
    {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "client_credentials",
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
