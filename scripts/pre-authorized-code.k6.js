import { check } from "k6";
import { isJwt, issueCredential, options } from "./flow-helpers.js";

export { options };

export default function () {
  const credential = issueCredential();

  check({ credential }, {
    "pre-authorized credential flow completes": ({ credential }) =>
      isJwt(credential),
  });
}
