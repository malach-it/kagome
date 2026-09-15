import { readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = join(scriptDirectory, "..");
const outputPath = join(repositoryRoot, "docs/flows/all.svg");
const temporaryPath = `${outputPath}.tmp`;

const graphs = [
  ["OAuth — Authorization Code Flow", "oauth/authorization_code.svg"],
  ["OAuth — Authorize Endpoint", "oauth/authorize_endpoint.svg"],
  ["OAuth — Client Credentials Flow", "oauth/client_credentials.svg"],
  ["OAuth — Code-Chain Flow", "oauth/code_chain.svg"],
  ["OAuth — Federation Callback Endpoint", "oauth/federation_callback.svg"],
  ["OAuth — Implicit Flow", "oauth/implicit.svg"],
  [
    "OAuth — Resource Owner Password Credentials Flow",
    "oauth/resource_owner_password_credentials.svg",
  ],
  ["OAuth — Token Endpoint", "oauth/token_endpoint.svg"],
  [
    "OAuth — Wallet Authorization Endpoint",
    "oauth/wallet_authorization_endpoint.svg",
  ],
  [
    "OpenID4VCI — Authorization Server Metadata Endpoint",
    "openid4vci/authorization_server_metadata_endpoint.svg",
  ],
  ["OpenID4VCI — Credential Endpoint", "openid4vci/credential_endpoint.svg"],
  [
    "OpenID4VCI — Credential Issuer Metadata Endpoint",
    "openid4vci/credential_issuer_metadata_endpoint.svg",
  ],
  [
    "OpenID4VCI — Credential Offer Endpoint",
    "openid4vci/credential_offer_endpoint.svg",
  ],
  ["OpenID4VCI — JWKS Endpoint", "openid4vci/jwks_endpoint.svg"],
  [
    "OpenID4VCI — Pre-Authorized Code Flow",
    "openid4vci/pre_authorized_code.svg",
  ],
  ["OpenID4VP — Presentation Flow", "openid4vp/presentation.svg"],
  [
    "OpenID4VP — Presentation Request Endpoint",
    "openid4vp/presentation_request_endpoint.svg",
  ],
  [
    "OpenID4VP — Presentation Response Endpoint",
    "openid4vp/presentation_response_endpoint.svg",
  ],
  [
    "SIOPv2 — Authorization Request Endpoint",
    "siopv2/authorization_request_endpoint.svg",
  ],
  ["SIOPv2 — Response Endpoint", "siopv2/response_endpoint.svg"],
  ["SIOPv2 — Flow", "siopv2/siopv2.svg"],
];

const columns = 6;
const cellWidth = 2000;
const cellHeight = 2200;
const horizontalPadding = 48;
const titleHeight = 72;
const verticalPadding = 48;
const availableWidth = cellWidth - horizontalPadding * 2;
const availableHeight = cellHeight - titleHeight - verticalPadding * 2;
const rows = Math.ceil(graphs.length / columns);
const canvasWidth = columns * cellWidth;
const canvasHeight = rows * cellHeight;
const sections = [];

for (const [index, [title, relativePath]] of graphs.entries()) {
  const path = join(repositoryRoot, "docs/flows", relativePath);
  const svg = await readFile(path, "utf8");
  const viewBox = svg.match(/viewBox="([^"]+)"/)?.[1];
  if (!viewBox) {
    throw new Error(`${relativePath} does not contain a viewBox`);
  }

  const [, , sourceWidth, sourceHeight] = viewBox.split(/\s+/).map(Number);
  if (!(sourceWidth > 0) || !(sourceHeight > 0)) {
    throw new Error(`${relativePath} has an invalid viewBox`);
  }

  const column = index % columns;
  const row = Math.floor(index / columns);
  const cellX = column * cellWidth;
  const cellY = row * cellHeight;
  const scale = Math.min(
    availableWidth / sourceWidth,
    availableHeight / sourceHeight,
  );
  const width = sourceWidth * scale;
  const height = sourceHeight * scale;
  const x = cellX + (cellWidth - width) / 2;
  const y = cellY + titleHeight + (availableHeight - height) / 2;
  const data = Buffer.from(svg).toString("base64");

  sections.push(
    `  <text x="${cellX + horizontalPadding}" y="${cellY + 42}" class="title">${escapeXml(title)}</text>`,
    `  <image x="${x}" y="${y}" width="${width}" height="${height}" href="data:image/svg+xml;base64,${data}"/>`,
  );
}

const document = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  `<svg xmlns="http://www.w3.org/2000/svg" width="${canvasWidth}" height="${canvasHeight}" viewBox="0 0 ${canvasWidth} ${canvasHeight}" role="img" aria-labelledby="title description">`,
  "  <title id=\"title\">Kagome identity flow graphs</title>",
  "  <desc id=\"description\">Landscape overview of all OAuth, OpenID4VCI, OpenID4VP, and SIOPv2 flow and endpoint graphs.</desc>",
  "  <style>.title { font: 700 28px sans-serif; fill: #222; }</style>",
  `  <rect width="${canvasWidth}" height="${canvasHeight}" fill="white"/>`,
  ...sections,
  "</svg>",
  "",
].join("\n");

await writeFile(temporaryPath, document, { mode: 0o644 });
await rename(temporaryPath, outputPath);

function escapeXml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}
