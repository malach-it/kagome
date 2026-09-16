import { check } from "k6";
import {
  authorize,
  json,
  location,
  options,
  parameters,
  redirectUri,
} from "./flow-helpers.js";

export { options };

export default function () {
  const response = authorize("token");
  const target = location(response);
  const fragment = parameters(target.replace("?", "#"));

  check(response, {
    "implicit grant redirects to the client": (result) =>
      result.status === 302 && target.startsWith(`${redirectUri}#`),
    "implicit grant returns a bearer token": () =>
      fragment.token_type === "bearer" &&
      typeof fragment.access_token === "string" &&
      fragment.access_token.length > 0,
    "implicit grant preserves client state": () => fragment.state === "k6-state",
    "implicit grant does not return an error": () =>
      json(response).error === undefined && fragment.error === undefined,
  });
}
