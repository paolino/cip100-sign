#!/usr/bin/env node
// CIP-100 body hash signer for Cardano
// Reads xprv (bech32) from stdin, derives the signing key, signs the body hash.
// Private key never touches disk.

import { createInterface } from 'readline';
import {
  decodeBech32, deriveCip1852, publicKeyFromScalar, keyHash,
  signExtended, verify, bytesToHex, hexToBytes,
} from './lib.mjs';

const BODY_HASH = '775ec0cac4003d3479ecafcf94771321026e6b5b777762dd9f94d416848ffdc3';
const TREASURY_KEY_HASH = '8bd03209d227956aaf9670751e0aa2057b51c1537a43f155b24fb1c1';
const AUTHOR_NAME = 'paolino';

const DERIVATION_PATHS = [
  { path: [1852, 1815, 0, 2, 0], label: "m/1852'/1815'/0'/2/0 (stake key)" },
  { path: [1852, 1815, 0, 0, 0], label: "m/1852'/1815'/0'/0/0 (payment key 0)" },
  { path: [1852, 1815, 0, 0, 1], label: "m/1852'/1815'/0'/0/1 (payment key 1)" },
  { path: [1852, 1815, 0, 1, 0], label: "m/1852'/1815'/0'/1/0 (change key 0)" },
];

async function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    const rl = createInterface({ input: process.stdin, terminal: false });
    rl.on('line', (line) => { data += line.trim(); });
    rl.on('close', () => resolve(data.trim()));
  });
}

function extractXprv(input) {
  try {
    const json = JSON.parse(input);
    if (json.wallet?.rootKey?.prv) return json.wallet.rootKey.prv;
    if (json.rootKey?.prv) return json.rootKey.prv;
    if (json.prv) return json.prv;
  } catch {}
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

  let matchedXsk = null;
  let matchedPub = null;
  let matchedLabel = null;

  for (const { path, label } of DERIVATION_PATHS) {
    const childXsk = deriveCip1852(xsk, path);
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

  const hashBytes = hexToBytes(BODY_HASH);
  const signature = signExtended(hashBytes, matchedXsk);
  const sigHex = bytesToHex(signature);
  const pubHex = bytesToHex(matchedPub);

  const valid = verify(signature, hashBytes, matchedPub);
  process.stderr.write(`Signature valid: ${valid}\n\n`);

  if (!valid) {
    process.stderr.write('ERROR: Signature verification failed!\n');
    process.exit(1);
  }

  const authorEntry = {
    name: AUTHOR_NAME,
    witness: {
      witnessAlgorithm: "ed25519",
      publicKey: pubHex,
      signature: sigHex
    }
  };

  process.stdout.write(JSON.stringify(authorEntry, null, 2) + '\n');

  matchedXsk.fill(0);
  xsk.fill(0);

  process.stderr.write('Done. Key material cleared from memory.\n');
}

main().catch(err => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});
