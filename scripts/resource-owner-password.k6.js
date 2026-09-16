import { check } from "k6";
import http from "k6/http";
import {
  clientId,
  clientSecret,
  formOptions,
  json,
  options,
  password,
  serverTarget,
  username,
} from "./flow-helpers.js";

export { options };

export default function () {
  const response = http.post(
    `${serverTarget}/token`,
    {
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "password",
      username,
      password,
    },
    formOptions("POST /token"),
  );
  const body = json(response);

  check(response, {
    "password grant succeeds": (result) => result.status === 200,
    "password grant returns a bearer token": () =>
      body.token_type === "bearer" &&
      typeof body.access_token === "string" &&
      body.access_token.length > 0,
    "password grant returns an expiry": () => body.expires_in === 3600,
  });
}
