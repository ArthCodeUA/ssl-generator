import { createHash } from "crypto";

export function b64(bytes) {
  const str64 =
    typeof bytes === "string"
      ? global.btoa(bytes)
      : global.btoa(String.fromCharCode.apply(null, bytes));
  return str64.replace(/\//g, "_").replace(/\+/g, "-").replace(/=/g, "");
}

export function clearB64(str64) {
  return str64
    .replace(/\//g, "_")
    .replace(/\+/g, "-")
    .replace(/=/g, "")
    .replace("\n", "");
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest();
}

export function hex2b64(hex) {
  const OPENSSL_HEX = /(?:\(stdin\)= |)([a-f\d]{512,1024})/;
  if (!OPENSSL_HEX.test(hex)) {
    return null;
  }
  hex = OPENSSL_HEX.exec(hex)[1];
  const bytes = [];
  while (hex.length >= 2) {
    bytes.push(parseInt(hex.substring(0, 2), 16));
    hex = hex.substring(2, hex.length);
  }
  return b64(new Uint8Array(bytes));
}
