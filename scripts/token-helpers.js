import http from "k6/http";

export const options = {
  vus: Number(__ENV.K6_VUS || "4"),
  duration: __ENV.K6_DURATION || "30s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500"],
  },
};

export const tokenTarget =
  __ENV.KAGOME_TOKEN_TARGET || "http://kagome:4000/token";
export const serverTarget =
  __ENV.KAGOME_SERVER_TARGET || tokenTarget.replace(/\/token$/, "");

export const clientId = __ENV.KAGOME_CLIENT_ID || "client_id";
export const clientSecret = __ENV.KAGOME_CLIENT_SECRET || "client_secret";
const publicHost = __ENV.KAGOME_PUBLIC_HOST || "localhost:4000";
const redirectUri =
  __ENV.KAGOME_REDIRECT_URI || "https://client.example.com/callback";
const username = __ENV.KAGOME_USERNAME || "username";
const password = __ENV.KAGOME_PASSWORD || "password";
export const idTokenClientId = `${username}@${publicHost}`;
const pkceVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
export const pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

export function formHeaders() {
  return {
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
  };
}

export function tokenChecks(expected) {
  return {
    "status is 200": (response) => response.status === 200,
    "token_type is bearer": (_response, payload) =>
      payload.token_type === expected.token_type,
    "access_token is present": (_response, payload) =>
      typeof payload.access_token === "string" && payload.access_token.length > 0,
    "expires_in is valid": (_response, payload) =>
      payload.expires_in === expected.expires_in,
    "authorization_code is omitted": (_response, payload) =>
      payload.authorization_code === undefined,
  };
}

export function authorizationCodeChecks() {
  return {
    "status is 200": (response) => response.status === 200,
    "authorization_code is present": (_response, payload) =>
      typeof payload.authorization_code === "string" &&
      payload.authorization_code.length > 0,
    "expires_in is valid": (_response, payload) => payload.expires_in === 600,
    "access_token is omitted": (_response, payload) =>
      payload.access_token === undefined,
  };
}

export function runChecks(response, checks) {
  const payload = response.json();
  const wrappedChecks = Object.fromEntries(
    Object.entries(checks).map(([name, assertion]) => [
      name,
      (response) => assertion(response, payload),
    ]),
  );

  return { payload, wrappedChecks };
}

export function validIdToken() {
  const { parameters, response } = authorize({
    response_type: "id_token",
    state: "k6-id-token-state",
  });
  requireAuthorizationParameter(response, parameters, "id_token");

  return parameters.id_token;
}

export function validHybridGrant() {
  const { parameters, response } = authorize({
    response_type: "code id_token",
    state: "k6-hybrid-state",
    code_challenge: pkceChallenge,
    code_challenge_method: "S256",
  });
  requireAuthorizationParameter(response, parameters, "code");
  requireAuthorizationParameter(response, parameters, "id_token");

  return {
    authorizationCode: parameters.code,
    codeVerifier: pkceVerifier,
    idToken: parameters.id_token,
  };
}

function authorize(requestParameters) {
  const requestClientId = `${username}:${password}@${publicHost}`;
  const query = formEncode({
    ...requestParameters,
    client_id: requestClientId,
    redirect_uri: redirectUri,
  });
  const response = http.get(`${serverTarget}/authorize?${query}`, {
    redirects: 0,
    headers: { Host: publicHost },
    tags: { name: "GET /authorize (id_token)" },
  });
  const location = response.headers.Location || response.headers.location || "";
  const queryString = location.includes("?")
    ? location.slice(location.indexOf("?") + 1).split("#", 1)[0]
    : "";
  const fragment = location.includes("#") ? location.split("#", 2)[1] : "";
  const parameters = {
    ...formDecode(queryString),
    ...formDecode(fragment),
  };

  return { parameters, response };
}

function requireAuthorizationParameter(response, parameters, name) {
  if (response.status !== 302 || !parameters[name]) {
    let responseBody = {};
    try {
      responseBody = response.json();
    } catch (_error) {
      responseBody = {};
    }
    const error =
      parameters.error || responseBody.error || "invalid_id_token_response";
    const description =
      parameters.error_description ||
      responseBody.error_description ||
      response.body ||
      `expected ${name} in an authorization redirect, received HTTP ${response.status}`;
    throw new Error(`${error}: ${description}`);
  }
}

function formEncode(values) {
  return Object.entries(values)
    .map(
      ([name, value]) =>
        `${encodeURIComponent(name)}=${encodeURIComponent(value)}`,
    )
    .join("&");
}

function formDecode(value) {
  return Object.fromEntries(
    value
      .split("&")
      .filter((entry) => entry.length > 0)
      .map((entry) => {
        const [name, encodedValue = ""] = entry.split("=", 2);
        return [
          decodeURIComponent(name.replace(/\+/g, " ")),
          decodeURIComponent(encodedValue.replace(/\+/g, " ")),
        ];
      }),
  );
}
