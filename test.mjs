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
  kL[31] &= 0x7f;
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
const GOLDEN_STAKE_PUB = 'c2d1a890f357e990ebac59ffe583eb415eb979963dd7207526c5a6ddf6a72e2d';
const GOLDEN_KEY_HASH = 'e4aade41feb2d4aff5515c68b47af9382850206a26e938468e8fe6e2';
const GOLDEN_SIG = '0d980a13f85db2aff0b332c9af050680e66302c6451944371966ffcaf59a0e7c92a1870304f06bdd0fa4192e3ac251723157b7216f3089bc5e49325a7a083a0e';

assert(bytesToHex(stakePub) === GOLDEN_STAKE_PUB, `Golden public key: ${bytesToHex(stakePub)}`);
assert(bytesToHex(hash) === GOLDEN_KEY_HASH, `Golden key hash: ${bytesToHex(hash)}`);
assert(bytesToHex(sig) === GOLDEN_SIG, `Golden signature: ${bytesToHex(sig)}`);

// Summary
process.stderr.write(`\n${failures === 0 ? 'All tests passed' : failures + ' test(s) failed'}\n`);
process.exit(failures === 0 ? 0 : 1);
