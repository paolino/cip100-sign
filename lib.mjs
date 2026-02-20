// CIP-100 signing library — BIP32-Ed25519 derivation and extended key signing

import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { bech32 } from 'bech32';

export { bytesToHex, hexToBytes };

export const ED25519_ORDER = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;

// --- Byte helpers ---

export function concat(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

export function le32(n) {
  const buf = new Uint8Array(4);
  buf[0] = n & 0xff;
  buf[1] = (n >> 8) & 0xff;
  buf[2] = (n >> 16) & 0xff;
  buf[3] = (n >> 24) & 0xff;
  return buf;
}

export function bytesToBigIntLE(bytes) {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

export function bigIntToBytesLE(n, length) {
  const bytes = new Uint8Array(length);
  let val = n < 0n ? n + (1n << BigInt(length * 8)) : n;
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(val & 0xFFn);
    val >>= 8n;
  }
  return bytes;
}

// --- Bech32 decoding ---

export function decodeBech32(str) {
  const decoded = bech32.decode(str, 200);
  return {
    hrp: decoded.prefix,
    bytes: new Uint8Array(bech32.fromWords(decoded.words)),
  };
}

// --- BIP32-Ed25519 (Cardano/Icarus variant) ---

export function publicKeyFromScalar(kL) {
  // Reduce modulo group order — Cardano's clamped scalars can exceed L
  // (bit 254 is set, L ≈ 2^252.6). Mathematically equivalent since B has order L.
  let scalar = bytesToBigIntLE(kL) % ED25519_ORDER;
  if (scalar === 0n) scalar = 1n; // should never happen with valid keys
  const point = ed25519.ExtendedPoint.BASE.multiply(scalar);
  return point.toRawBytes();
}

export function keyHash(pubkey) {
  return blake2b(pubkey, { dkLen: 28 });
}

export function deriveChild(xsk, index) {
  const kL = xsk.slice(0, 32);
  const kR = xsk.slice(32, 64);
  const cc = xsk.slice(64, 96);
  const indexBytes = le32(index);

  let Z, C;
  if (index >= 0x80000000) {
    Z = hmac(sha512, cc, concat(new Uint8Array([0x00]), kL, kR, indexBytes));
    C = hmac(sha512, cc, concat(new Uint8Array([0x01]), kL, kR, indexBytes));
  } else {
    const A = publicKeyFromScalar(kL);
    Z = hmac(sha512, cc, concat(new Uint8Array([0x02]), A, indexBytes));
    C = hmac(sha512, cc, concat(new Uint8Array([0x03]), A, indexBytes));
  }

  const zL = Z.slice(0, 28);
  const zR = Z.slice(32, 64);

  const zL_big = bytesToBigIntLE(zL);
  const kL_big = bytesToBigIntLE(kL);
  const child_kL_big = zL_big * 8n + kL_big;

  // Store as 32 bytes; reduction mod L happens at point multiplication / signing time
  const child_kL = bigIntToBytesLE(child_kL_big, 32);

  const zR_big = bytesToBigIntLE(zR);
  const kR_big = bytesToBigIntLE(kR);
  const child_kR_big = (zR_big + kR_big) % (1n << 256n);
  const child_kR = bigIntToBytesLE(child_kR_big, 32);

  const child_cc = C.slice(32, 64);

  return concat(child_kL, child_kR, child_cc);
}

export function derivePath(xsk, indices) {
  let key = xsk;
  for (const index of indices) {
    key = deriveChild(key, index);
  }
  return key;
}

// Derive using CIP-1852 convention: first 3 hardened, rest soft
export function deriveCip1852(xsk, path) {
  const indices = path.map((p, i) => i < 3 ? p + 0x80000000 : p);
  return derivePath(xsk, indices);
}

// --- Ed25519 extended key signing ---

export function signExtended(message, xsk) {
  const kL = xsk.slice(0, 32);
  const kR = xsk.slice(32, 64);
  const A = publicKeyFromScalar(kL);
  const kL_scalar = bytesToBigIntLE(kL);

  const r_hash = sha512(concat(kR, message));
  const r = bytesToBigIntLE(r_hash) % ED25519_ORDER;

  const R_point = ed25519.ExtendedPoint.BASE.multiply(r);
  const R_bytes = R_point.toRawBytes();

  const h_hash = sha512(concat(R_bytes, A, message));
  const h = bytesToBigIntLE(h_hash) % ED25519_ORDER;

  const S = (r + h * kL_scalar) % ED25519_ORDER;
  const S_bytes = bigIntToBytesLE(S, 32);

  return concat(R_bytes, S_bytes);
}

export function verify(signature, message, publicKey) {
  return ed25519.verify(signature, message, publicKey);
}
