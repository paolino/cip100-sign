#!/usr/bin/env node
// Golden test: generate a fresh BIP32-Ed25519 root key, derive a child,
// sign a known message, verify the signature.

import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { bech32 } from 'bech32';
import {
  concat, bytesToBigIntLE, bigIntToBytesLE,
  decodeBech32, deriveCip1852, publicKeyFromScalar, keyHash,
  signExtended, verify, bytesToHex, hexToBytes,
} from './lib.mjs';

// --- Generate a deterministic test root key ---
// We use a fixed seed (NOT for production — test only)

const TEST_SEED = hexToBytes(
  'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf' +
  'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
);

// Derive root extended key from seed (simplified Icarus-style)
function rootKeyFromSeed(seed) {
  const h = hmac(sha512, new TextEncoder().encode('ed25519 cardano seed'), seed);
  const kL = new Uint8Array(h.slice(0, 32));
  // Clamp
  kL[0] &= 0xf8;
  kL[31] &= 0x1f;
  kL[31] |= 0x40;
  const kR = new Uint8Array(h.slice(32, 64));
  // Chain code from second HMAC
  const cc = hmac(sha512, new TextEncoder().encode('ed25519 cardano chaincode'), seed).slice(0, 32);
  return concat(kL, kR, new Uint8Array(cc));
}

function encodeBech32(hrp, bytes) {
  return bech32.encode(hrp, bech32.toWords(bytes), 200);
}

// --- Test ---

let failures = 0;

function assert(condition, msg) {
  if (!condition) {
    process.stderr.write(`FAIL: ${msg}\n`);
    failures++;
  } else {
    process.stderr.write(`PASS: ${msg}\n`);
  }
}

// 1. Generate root key
const rootXsk = rootKeyFromSeed(TEST_SEED);
assert(rootXsk.length === 96, 'Root key is 96 bytes');

// 2. Derive public key from root
const rootPub = publicKeyFromScalar(rootXsk.slice(0, 32));
assert(rootPub.length === 32, 'Root public key is 32 bytes');

// 3. Encode as bech32 and decode back
const xprvBech32 = encodeBech32('xprv', rootXsk);
const decoded = decodeBech32(xprvBech32);
assert(decoded.hrp === 'xprv', 'Bech32 round-trip HRP');
assert(bytesToHex(decoded.bytes) === bytesToHex(rootXsk), 'Bech32 round-trip data');

// 4. Derive stake key at m/1852'/1815'/0'/2/0
const stakeXsk = deriveCip1852(rootXsk, [1852, 1815, 0, 2, 0]);
assert(stakeXsk.length === 96, 'Derived key is 96 bytes');

const stakePub = publicKeyFromScalar(stakeXsk.slice(0, 32));
assert(stakePub.length === 32, 'Derived public key is 32 bytes');

// 5. Key hash
const hash = keyHash(stakePub);
assert(hash.length === 28, 'Key hash is 28 bytes');

// 6. Sign a test message
const testMessage = hexToBytes('deadbeefcafebabe00112233445566778899aabbccddeeff0011223344556677');
const sig = signExtended(testMessage, stakeXsk);
assert(sig.length === 64, 'Signature is 64 bytes');

// 7. Verify signature
const valid = verify(sig, testMessage, stakePub);
assert(valid, 'Signature verifies with derived public key');

// 8. Verify fails with wrong key
const paymentXsk = deriveCip1852(rootXsk, [1852, 1815, 0, 0, 0]);
const paymentPub = publicKeyFromScalar(paymentXsk.slice(0, 32));
const invalidVerify = verify(sig, testMessage, paymentPub);
assert(!invalidVerify, 'Signature fails with wrong public key');

// 9. Verify fails with wrong message
const wrongMsg = hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
const invalidMsg = verify(sig, wrongMsg, stakePub);
assert(!invalidMsg, 'Signature fails with wrong message');

// 10. Determinism: signing same message with same key produces same signature
const sig2 = signExtended(testMessage, stakeXsk);
assert(bytesToHex(sig) === bytesToHex(sig2), 'Signing is deterministic');

// 11. Golden values (pinned from first successful run)
const GOLDEN_STAKE_PUB = '1ac89c2e2402fe83b7f7b0c4f230c16ef2ca8a50a502b7275e5b131c76bb00e3';
const GOLDEN_KEY_HASH = '7a7b0af6db7d1930c44db17133fcfe962614c51f8f48b5aef4b8b482';
const GOLDEN_SIG = '1430afe873e54eb039df0dc4642b66158254c0b311c3eb9016d4aac7d4f9380c5213e7e26cc965690b1fa69d6614051725ac3e47e0ab9d5f5161fa5af2dbdd08';

assert(bytesToHex(stakePub) === GOLDEN_STAKE_PUB, `Golden public key: ${bytesToHex(stakePub)}`);
assert(bytesToHex(hash) === GOLDEN_KEY_HASH, `Golden key hash: ${bytesToHex(hash)}`);
assert(bytesToHex(sig) === GOLDEN_SIG, `Golden signature: ${bytesToHex(sig)}`);

// --- Cross-validation with cardano-signer 1.34.0 ---
// These values were produced by cardano-signer with the same extended key.

// Extended key: kL = 6432be..., kR = 00..00 (test key)
const csKL = hexToBytes('6432be5b587ab78abe263367672b599fda4b9c55b78c07e976441f2b6bf6a62a');
const csKR = new Uint8Array(32);
const csCC = new Uint8Array(32);
const csXsk = concat(csKL, csKR, csCC);
const csHash = hexToBytes('deadbeefcafebabe00112233445566778899aabbccddeeff0011223344556677');

// cardano-signer output for this extended key + hash
const CS_PUBKEY = '59d5344abe4c02b790621c1367f178f0c5948b503764e93135c7dc4b6a2f6624';
const CS_SIG = '695eb83585cc35ed1582a6bb82e79394f50adef5b1bf7bac8b921bfab7a269cfd0c8a676bdc23c60013affb469be8793ff5736d93cb89c5d7165023db3959906';

const ourPub = publicKeyFromScalar(csKL);
const ourSig = signExtended(csHash, csXsk);

assert(bytesToHex(ourPub) === CS_PUBKEY, 'Cross-check: pubkey matches cardano-signer');
assert(bytesToHex(ourSig) === CS_SIG, 'Cross-check: signature matches cardano-signer');
assert(verify(hexToBytes(CS_SIG), csHash, hexToBytes(CS_PUBKEY)), 'Cross-check: cardano-signer sig verifies');

// --- Golden test: JSON-LD canonicalization + blake2b-256 body hash ---
// Verifies that our canonicalization pipeline produces the expected N-Quads
// and body hash for a known CIP-100 document.

const { blake2b } = await import('@noble/hashes/blake2b');
const jsonld = (await import('jsonld')).default;

const GOLDEN_DOC = {
  "@context": {
    "@language": "en",
    "CIP100": "https://github.com/cardano-foundation/CIPs/blob/master/CIP-0100/README.md",
    "CIP108": "https://github.com/cardano-foundation/CIPs/blob/master/CIP-0108/README.md",
    "hashAlgorithm": "CIP100:hashAlgorithm",
    "body": {
      "@id": "CIP108:body",
      "@context": {
        "references": {
          "@id": "CIP108:references",
          "@container": "@set",
          "@context": {
            "GovernanceMetadata": "CIP100:GovernanceMetadataReference",
            "Other": "CIP100:OtherReference",
            "label": "CIP100:reference-label",
            "uri": "CIP100:reference-uri",
            "referenceHash": {
              "@id": "CIP108:referenceHash",
              "@context": {
                "hashDigest": "CIP108:hashDigest",
                "hashAlgorithm": "CIP100:hashAlgorithm"
              }
            }
          }
        },
        "title": "CIP108:title",
        "abstract": "CIP108:abstract",
        "motivation": "CIP108:motivation",
        "rationale": "CIP108:rationale"
      }
    },
    "authors": {
      "@id": "CIP100:authors",
      "@container": "@set",
      "@context": {
        "name": "http://xmlns.com/foaf/0.1/name",
        "witness": {
          "@id": "CIP100:witness",
          "@context": {
            "witnessAlgorithm": "CIP100:witnessAlgorithm",
            "publicKey": "CIP100:publicKey",
            "signature": "CIP100:signature"
          }
        }
      }
    }
  },
  "body": {
    "title": "Test Proposal",
    "abstract": "A test proposal for golden value verification.",
    "motivation": "Testing canonicalization.",
    "rationale": "Ensures deterministic output.",
    "references": []
  }
};

const GOLDEN_NQUADS =
  '_:c14n0 <CIP108:body> _:c14n1 .\n' +
  '_:c14n1 <CIP108:abstract> "A test proposal for golden value verification."@en .\n' +
  '_:c14n1 <CIP108:motivation> "Testing canonicalization."@en .\n' +
  '_:c14n1 <CIP108:rationale> "Ensures deterministic output."@en .\n' +
  '_:c14n1 <CIP108:title> "Test Proposal"@en .\n';

const GOLDEN_BODY_HASH = '440b4834b8f3c253dba1abb3c661be1335a01e72ee67be60a8c26ea5432ec33c';

const reduced = { "@context": GOLDEN_DOC["@context"], body: GOLDEN_DOC.body };
const nquads = await jsonld.canonize(reduced, { algorithm: 'URDNA2015', format: 'application/n-quads' });

assert(nquads === GOLDEN_NQUADS, 'Canonicalization produces expected N-Quads');

const bodyHash = bytesToHex(blake2b(new TextEncoder().encode(nquads), { dkLen: 32 }));
assert(bodyHash === GOLDEN_BODY_HASH, `Body hash: ${bodyHash}`);

// --- Golden test: N-Quads rendering with rich content ---
// Exercises: newlines, markdown tables, $dollar signs, "quotes", \\backslashes,
// \ttabs, unicode (₳ — é è ê), Japanese (カルダノ), IPFS URIs, multiple references.

const RICH_DOC_BODY = {
  "title": "Treasury Withdrawal \u2014 Q1 2026",
  "abstract": "This proposal requests **\u20b310,142,000** for the Amaru project.\nIt covers 12 months of development across 4 scopes.",
  "motivation": "#### Budget Breakdown\n\n| Scope | FTEs | Fixed |\n| :--- | ---: | ---: |\n| Core Development | 3.5 | $500k |\n| Operations | 2 | $130k |\n\n> **NOTE**: The $225k yearly rate includes contractor overhead.\n\nSee [details](ipfs://bafybeidrfx7yxy54xg7crp2n4s2uxflmxaafebf5py4xi2ze75nya3sp5a) for the full breakdown.",
  "rationale": "Line 1\nLine 2\n\nParagraph with \"quotes\" and a backslash: \\\\ and a tab:\tand unicode: \u00e9\u00e8\u00ea",
  "references": [
    {
      "@type": "Other",
      "label": "Budget Breakdown",
      "uri": "ipfs://bafybeidrfx7yxy54xg7crp2n4s2uxflmxaafebf5py4xi2ze75nya3sp5a"
    },
    {
      "@language": "ja",
      "@type": "Other",
      "label": "\u30ab\u30eb\u30c0\u30ce\u30d6\u30ed\u30c3\u30af\u30c1\u30a7\u30fc\u30f3",
      "uri": "ipfs://bafybeifwrhggaa7miqr6s7lqvtphjnzhpcvagxfjn5bjipme3pzamvikiy"
    }
  ]
};

const RICH_BODY_HASH = '2133111962935897a321dc3030d6bb9fc75ba83926635ade90129fda1a31a9bb';

const richReduced = { "@context": GOLDEN_DOC["@context"], body: RICH_DOC_BODY };
const richNquads = await jsonld.canonize(richReduced, { algorithm: 'URDNA2015', format: 'application/n-quads' });
const richHash = bytesToHex(blake2b(new TextEncoder().encode(richNquads), { dkLen: 32 }));

assert(richNquads.length === 1281, `Rich N-Quads length: ${richNquads.length}`);
assert(richNquads.includes('$500k'), 'N-Quads preserves dollar signs');
assert(richNquads.includes('\u20b310,142,000'), 'N-Quads preserves ₳ symbol');
assert(richNquads.includes('\u2014'), 'N-Quads preserves em-dash');
assert(richNquads.includes('\u00e9\u00e8\u00ea'), 'N-Quads preserves accented chars');
assert(richNquads.includes('\u30ab\u30eb\u30c0\u30ce'), 'N-Quads preserves Japanese');
assert(richNquads.includes('\\n'), 'N-Quads escapes newlines');
assert(richNquads.includes('\\"quotes\\"'), 'N-Quads escapes quotes');
assert(richNquads.includes('\\\\'), 'N-Quads escapes backslashes');
assert(richHash === RICH_BODY_HASH, `Rich body hash: ${richHash}`);

// Summary
process.stderr.write(`\n${failures === 0 ? 'All tests passed' : failures + ' test(s) failed'}\n`);
process.exit(failures === 0 ? 0 : 1);
