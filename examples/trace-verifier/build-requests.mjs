import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Regenerates the *-request.json bodies in this directory from the vector files
// in the repository, so a new vector only needs the record dropped next to it.
const OUT = dirname(fileURLToPath(import.meta.url));
const REPO = join(OUT, "..", "..");
const vector = (name) => readFileSync(join(REPO, "vectors", "trace", "bernstein", name), "utf8").trim();
const write = (name, text) => writeFileSync(join(OUT, name), text);

const singleText = vector("single-execution-trust-record.json");
const parentText = vector("delegated-parent-trust-record.json");
const childText = vector("delegated-child-trust-record.json");

// -- case (a): valid record, passed as raw text (byte-exact form) --------------
const caseA = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "verify_trace_record", arguments: { record: singleText } } };
write("a-request.json", JSON.stringify(caseA));

// -- case (b): same record, signature tampered by one character ----------------
const single = JSON.parse(singleText);
const origSig = single.signature;
if (origSig[0] === "K") throw new Error("pick a different index, collides after flip");
const tamperedSig = (origSig[0] === "k" ? "K" : origSig[0] === "A" ? "B" : "A") + origSig.slice(1);
if (tamperedSig === origSig) throw new Error("tamper produced no change");
const tampered = { ...single, signature: tamperedSig };
const tamperedText = JSON.stringify(tampered); // re-serialized; fine since we're testing the signature check, not byte-exact hashing
write("b-tampered-signature-record.json", tamperedText + "\n");
const caseB = { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "verify_trace_record", arguments: { record: tamperedText } } };
write("b-request.json", JSON.stringify(caseB));
console.log("original signature :", origSig);
console.log("tampered signature :", tamperedSig);

// -- case (c): delegation chain, parent+child, WITH a trust context ------------
const parentJwk = JSON.parse(parentText).cnf.jwk;
const rootJwk = { kty: parentJwk.kty, crv: parentJwk.crv, x: parentJwk.x }; // kid dropped; identity is (kty,crv,x,y) only
const child = JSON.parse(childText);
const parent = JSON.parse(parentText);
const credId = child.delegation.credential_id;
const contextWith = {
  trusted_root_keys: [rootJwk],
  credentials: {
    [credId]: {
      issuer: parent.subject,
      holder: child.subject,
      not_before: child.iat - 60,
      not_after: child.iat + 60,
    },
  },
};
const caseC = {
  jsonrpc: "2.0",
  id: 3,
  method: "tools/call",
  params: { name: "verify_delegation_chain", arguments: { records: [parentText, childText], context: contextWith } },
};
write("c-request.json", JSON.stringify(caseC));
write("c-context.json", JSON.stringify(contextWith, null, 2) + "\n");

// -- case (d): same chain, WITHOUT any trust context ----------------------------
const caseD = {
  jsonrpc: "2.0",
  id: 4,
  method: "tools/call",
  params: { name: "verify_delegation_chain", arguments: { records: [parentText, childText] } },
};
write("d-request.json", JSON.stringify(caseD));

console.log("wrote a/b/c/d request bodies to", OUT);
