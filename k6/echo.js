import http from "k6/http";
import { check } from "k6";

export const options = {
  vus: Number(__ENV.K6_VUS || "4"),
  duration: __ENV.K6_DURATION || "30s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500"],
  },
};

const target = __ENV.KAGOME_TARGET || "http://kagome:4000/echo";

export default function () {
  const response = http.get(target, {
    headers: {
      "x-kagome-test": "k6",
    },
  });

  const payload = response.json();

  check(response, {
    "status is 200": (response) => response.status === 200,
    "method is get": () => payload.method === "GET",
    "path is echo": () => payload.path === "/echo",
    "protocol is http 1.1": () => payload.protocol === "HTTP/1.1",
    "body is empty": () => payload.body === "",
    "custom header is echoed": () =>
      payload.headers.some(
        (header) =>
          header.name.toLowerCase() === "x-kagome-test" &&
          header.value === "k6",
      ),
  });
}
