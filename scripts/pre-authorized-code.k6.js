import { check } from "k6";
import { isJwt, issueCredential, options } from "./flow-helpers.js";

export { options };

export default async function () {
  const credential = await issueCredential();

  check({ credential }, {
    "pre-authorized credential flow completes": ({ credential }) =>
      isJwt(credential),
  });
}
