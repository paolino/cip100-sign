#!/usr/bin/env node
// CIP-100 body hash signer for Cardano
// Reads xprv (bech32) from stdin, derives the signing key, signs the body hash.
// Private key never touches disk.

import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { bech32 } from 'bech32';
import { createInterface } from 'readline';

// --- Constants ---

const BODY_HASH = '775ec0cac4003d3479ecafcf94771321026e6b5b777762dd9f94d416848ffdc3';
const TREASURY_KEY_HASH = '8bd03209d227956aaf9670751e0aa2057b51c1537a43f155b24fb1c1';
const AUTHOR_NAME = 'paolino';
const ED25519_ORDER = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;

// CIP-1852 derivation paths to try
const DERIVATION_PATHS = [
  { path: [1852, 1815, 0, 2, 0], label: "m/1852'/1815'/0'/2/0 (stake key)" },
  { path: [1852, 1815, 0, 0, 0], label: "m/1852'/1815'/0'/0/0 (payment key 0)" },
  { path: [1852, 1815, 0, 0, 1], label: "m/1852'/1815'/0'/0/1 (payment key 1)" },
  { path: [1852, 1815, 0, 1, 0], label: "m/1852'/1815'/0'/1/0 (change key 0)" },
];

// --- Byte helpers ---

function concat(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function le32(n) {
  const buf = new Uint8Array(4);
  buf[0] = n & 0xff;
  buf[1] = (n >> 8) & 0xff;
  buf[2] = (n >> 16) & 0xff;
  buf[3] = (n >> 24) & 0xff;
  return buf;
}

function bytesToBigIntLE(bytes) {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function bigIntToBytesLE(n, length) {
  const bytes = new Uint8Array(length);
  let val = n < 0n ? n + (1n << BigInt(length * 8)) : n;
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(val & 0xFFn);
    val >>= 8n;
  }
  return bytes;
}

// --- Bech32 decoding ---

function decodeBech32(str) {
  // Try bech32, then bech32m
  try {
    const decoded = bech32.decode(str, 200);
    return { hrp: decoded.prefix, bytes: new Uint8Array(bech32.fromWords(decoded.words)) };
  } catch {
    // Some Cardano tools use bech32m
    const { bech32m } = await import('bech32');
    const decoded = bech32m.decode(str, 200);
    return { hrp: decoded.prefix, bytes: new Uint8Array(bech32m.fromWords(decoded.words)) };
  }
}

// --- BIP32-Ed25519 (Cardano/Icarus variant) ---

function publicKeyFromScalar(kL) {
  const scalar = bytesToBigIntLE(kL);
  const point = ed25519.ExtendedPoint.BASE.multiply(scalar);
  return point.toRawBytes();
}

function keyHash(pubkey) {
  return blake2b(pubkey, { dkLen: 28 });
}

function deriveChild(xsk, index) {
  const kL = xsk.slice(0, 32);
  const kR = xsk.slice(32, 64);
  const cc = xsk.slice(64, 96);
  const indexBytes = le32(index);

  let Z, C;
  if (index >= 0x80000000) {
    // Hardened derivation
    Z = hmac(sha512, cc, concat(new Uint8Array([0x00]), kL, kR, indexBytes));
    C = hmac(sha512, cc, concat(new Uint8Array([0x01]), kL, kR, indexBytes));
  } else {
    // Soft derivation
    const A = publicKeyFromScalar(kL);
    Z = hmac(sha512, cc, concat(new Uint8Array([0x02]), A, indexBytes));
    C = hmac(sha512, cc, concat(new Uint8Array([0x03]), A, indexBytes));
  }

  // zL is only 28 bytes (224 bits)
  const zL = Z.slice(0, 28);
  const zR = Z.slice(32, 64);

  // child_kL = 8 * zL + parent_kL (little-endian 256-bit arithmetic)
  const zL_big = bytesToBigIntLE(zL);
  const kL_big = bytesToBigIntLE(kL);
  const child_kL_big = zL_big * 8n + kL_big;

  // If child_kL >= order, derivation is invalid (very rare)
  if (child_kL_big >= ED25519_ORDER) {
    throw new Error('Child key derivation overflow — try a different index');
  }

  const child_kL = bigIntToBytesLE(child_kL_big, 32);

  // child_kR = (zR + parent_kR) mod 2^256
  const zR_big = bytesToBigIntLE(zR);
  const kR_big = bytesToBigIntLE(kR);
  const child_kR_big = (zR_big + kR_big) % (1n << 256n);
  const child_kR = bigIntToBytesLE(child_kR_big, 32);

  const child_cc = C.slice(32, 64);

  return concat(child_kL, child_kR, child_cc);
}

function derivePath(xsk, path) {
  let key = xsk;
  for (let i = 0; i < path.length; i++) {
    const index = i < 3
      ? path[i] + 0x80000000   // First 3 levels are hardened
      : path[i];                // Last 2 are soft
    key = deriveChild(key, index);
  }
  return key;
}

// --- Ed25519 extended key signing ---
// Cardano uses kR for nonce generation instead of SHA-512(sk)

function signExtended(message, xsk) {
  const kL = xsk.slice(0, 32);
  const kR = xsk.slice(32, 64);
  const A = publicKeyFromScalar(kL);
  const kL_scalar = bytesToBigIntLE(kL);

  // Nonce: r = SHA-512(kR || message) mod L
  const r_hash = sha512(concat(kR, message));
  const r = bytesToBigIntLE(r_hash) % ED25519_ORDER;

  // R = r * B
  const R_point = ed25519.ExtendedPoint.BASE.multiply(r);
  const R_bytes = R_point.toRawBytes();

  // h = SHA-512(R || A || message) mod L
  const h_hash = sha512(concat(R_bytes, A, message));
  const h = bytesToBigIntLE(h_hash) % ED25519_ORDER;

  // S = (r + h * kL_scalar) mod L
  const S = (r + h * kL_scalar) % ED25519_ORDER;
  const S_bytes = bigIntToBytesLE(S, 32);

  return concat(R_bytes, S_bytes);
}

// --- Main ---

async function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    const rl = createInterface({ input: process.stdin, terminal: false });
    rl.on('line', (line) => { data += line.trim(); });
    rl.on('close', () => resolve(data.trim()));
  });
}

function extractXprv(input) {
  // Try as JSON (Eternl export format)
  try {
    const json = JSON.parse(input);
    if (json.wallet?.rootKey?.prv) return json.wallet.rootKey.prv;
    if (json.rootKey?.prv) return json.rootKey.prv;
    if (json.prv) return json.prv;
  } catch {}
  // Assume raw bech32
  return input;
}

async function main() {
  process.stderr.write('Reading key from stdin...\n');
  const input = await readStdin();

  if (!input) {
    process.stderr.write('Error: no input received. Pipe your xprv bech32 or Eternl JSON export.\n');
    process.exit(1);
  }

  const xprvBech32 = extractXprv(input);
  const { bytes: xsk } = decodeBech32(xprvBech32);

  if (xsk.length !== 96) {
    process.stderr.write(`Error: expected 96 bytes for xprv, got ${xsk.length}\n`);
    process.exit(1);
  }

  process.stderr.write(`Target treasury key hash: ${TREASURY_KEY_HASH}\n`);
  process.stderr.write(`Body hash to sign: ${BODY_HASH}\n\n`);

  // Try each derivation path
  let matchedXsk = null;
  let matchedPub = null;
  let matchedLabel = null;

  for (const { path, label } of DERIVATION_PATHS) {
    const childXsk = derivePath(xsk, path);
    const childPub = publicKeyFromScalar(childXsk.slice(0, 32));
    const childHash = bytesToHex(keyHash(childPub));

    process.stderr.write(`  ${label}: ${childHash}`);

    if (childHash === TREASURY_KEY_HASH) {
      process.stderr.write(' ← MATCH\n');
      matchedXsk = childXsk;
      matchedPub = childPub;
      matchedLabel = label;
    } else {
      process.stderr.write('\n');
    }
  }

  if (!matchedXsk) {
    process.stderr.write('\nError: no derived key matches the treasury key hash.\n');
    process.stderr.write('This xprv may not be the correct wallet.\n');
    process.exit(1);
  }

  process.stderr.write(`\nSigning with key from ${matchedLabel}\n`);

  // Sign the body hash
  const hashBytes = hexToBytes(BODY_HASH);
  const signature = signExtended(hashBytes, matchedXsk);
  const sigHex = bytesToHex(signature);
  const pubHex = bytesToHex(matchedPub);

  // Verify with standard ed25519
  const valid = ed25519.verify(signature, hashBytes, matchedPub);
  process.stderr.write(`Signature valid: ${valid}\n\n`);

  if (!valid) {
    process.stderr.write('ERROR: Signature verification failed!\n');
    process.exit(1);
  }

  // Output CIP-100 author entry
  const authorEntry = {
    name: AUTHOR_NAME,
    witness: {
      witnessAlgorithm: "ed25519",
      publicKey: pubHex,
      signature: sigHex
    }
  };

  // Write JSON to stdout (only stdout output)
  process.stdout.write(JSON.stringify(authorEntry, null, 2) + '\n');

  // Clear sensitive data
  matchedXsk.fill(0);
  xsk.fill(0);

  process.stderr.write('Done. Key material cleared from memory.\n');
}

main().catch(err => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});
