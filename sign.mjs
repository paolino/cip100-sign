#!/usr/bin/env node
// CIP-100 body hash signer for Cardano
// Reads xprv (bech32) from stdin, derives the signing key, signs the body hash,
// and patches the proposal JSON (passed as argument) with the new author entry.
// Private key never touches disk.

import { readFileSync } from 'fs';
import { createInterface } from 'readline';
import {
  decodeBech32, deriveCip1852, publicKeyFromScalar, keyHash,
  signExtended, verify, bytesToHex, hexToBytes,
} from './lib.mjs';

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
    rl.on('line', (line) => { data += ' ' + line.trim(); });
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
  const proposalPath = process.argv[2];
  if (!proposalPath) {
    process.stderr.write('Usage: cip100-sign <proposal.json>\n');
    process.stderr.write('  Reads xprv from stdin, signs the body hash, outputs patched JSON to stdout.\n');
    process.exit(1);
  }

  const proposal = JSON.parse(readFileSync(proposalPath, 'utf-8'));

  if (proposal.hashAlgorithm !== 'blake2b-256') {
    process.stderr.write(`Error: unsupported hashAlgorithm "${proposal.hashAlgorithm}"\n`);
    process.exit(1);
  }

  // Compute the body hash from the proposal
  const { blake2b } = await import('@noble/hashes/blake2b');
  const jsonld = (await import('jsonld')).default;
  const reduced = { "@context": proposal["@context"], body: proposal.body };
  const nquads = await jsonld.canonize(reduced, { algorithm: 'URDNA2015', format: 'application/n-quads' });
  const BODY_HASH = bytesToHex(blake2b(new TextEncoder().encode(nquads), { dkLen: 32 }));

  process.stderr.write('Reading key from stdin...\n');
  const input = await readStdin();

  if (!input) {
    process.stderr.write('Error: no input received. Pipe your xprv (hex, bech32, or Eternl JSON).\n');
    process.exit(1);
  }

  const keyStr = extractXprv(input);

  // Detect mnemonic (words separated by spaces)
  const words = keyStr.trim().split(/\s+/);
  let xsk;

  if (words.length >= 12 && words.length <= 24 && words.every(w => /^[a-z]+$/.test(w))) {
    // Mnemonic phrase — derive root key via Icarus PBKDF2
    const { mnemonicToEntropy, validateMnemonic } = await import('@scure/bip39');
    const { wordlist } = await import('@scure/bip39/wordlists/english');
    const { pbkdf2 } = await import('@noble/hashes/pbkdf2');
    const { sha512 } = await import('@noble/hashes/sha512');

    const mnemonic = words.join(' ');
    if (!validateMnemonic(mnemonic, wordlist)) {
      process.stderr.write('Error: invalid mnemonic (checksum failed).\n');
      process.exit(1);
    }

    const entropy = mnemonicToEntropy(mnemonic, wordlist);
    const mnemonicBytes = new TextEncoder().encode(mnemonic);

    // Try both Icarus variants
    function clampAndCopy(buf) {
      const r = new Uint8Array(buf);
      r[0] &= 0xf8;
      r[31] &= 0x1f;
      r[31] |= 0x40;
      return r;
    }

    const { hmac } = await import('@noble/hashes/hmac');

    const variants = [
      { label: 'Icarus', raw: clampAndCopy(pbkdf2(sha512, new Uint8Array(0), entropy, { c: 4096, dkLen: 96 })) },
      { label: 'Icarus-V2', raw: clampAndCopy(pbkdf2(sha512, mnemonicBytes, new Uint8Array(0), { c: 4096, dkLen: 96 })) },
      { label: 'pw=entropy', raw: clampAndCopy(pbkdf2(sha512, entropy, new Uint8Array(0), { c: 4096, dkLen: 96 })) },
      { label: 'salt=mnemonic', raw: clampAndCopy(pbkdf2(sha512, new Uint8Array(0), mnemonicBytes, { c: 4096, dkLen: 96 })) },
    ];

    // BIP39 seed approach (Ledger-style)
    const bip39seed = pbkdf2(sha512, mnemonicBytes, new TextEncoder().encode('mnemonic'), { c: 2048, dkLen: 64 });
    const h = hmac(sha512, new TextEncoder().encode('ed25519 cardano seed'), bip39seed);
    const bkL = new Uint8Array(h.slice(0, 32));
    bkL[0] &= 0xf8; bkL[31] &= 0x1f; bkL[31] |= 0x40;
    const bkR = new Uint8Array(h.slice(32, 64));
    const { concat } = await import('./lib.mjs');
    const bcc = hmac(sha512, new TextEncoder().encode('ed25519 cardano chaincode'), bip39seed).slice(0, 32);
    variants.push({ label: 'BIP39+HMAC', raw: concat(bkL, bkR, new Uint8Array(bcc)) });

    process.stderr.write(`Key format: mnemonic (${words.length} words)\n`);
    process.stderr.write(`Trying ${variants.length} derivation variants × 10 accounts...\n\n`);

    let found = false;
    for (const { label, raw } of variants) {
      for (let acct = 0; acct < 10; acct++) {
        const acctXsk = deriveCip1852(raw, [1852, 1815, acct, 2, 0]);
        const acctPub = publicKeyFromScalar(acctXsk.slice(0, 32));
        const acctHash = bytesToHex(keyHash(acctPub));
        if (acctHash === TREASURY_KEY_HASH) {
          process.stderr.write(`  MATCH: ${label}, account ${acct}, m/1852'/1815'/${acct}'/2/0\n`);
          process.stderr.write(`  stake key hash: ${acctHash}\n`);
          xsk = raw;
          // Override derivation paths to use this account
          DERIVATION_PATHS.length = 0;
          DERIVATION_PATHS.push(
            { path: [1852, 1815, acct, 2, 0], label: `m/1852'/1815'/${acct}'/2/0 (stake key)` },
          );
          found = true;
          break;
        }
      }
      if (found) break;
    }

    if (!found) {
      process.stderr.write('No match found. Cross-check your xpub against these:\n\n');
      for (const { label, raw: r } of variants) {
        const rootPub = bytesToHex(publicKeyFromScalar(r.slice(0, 32)));
        process.stderr.write(`  ${label}:\n`);
        process.stderr.write(`    root pub: ${rootPub}\n`);
        for (let a = 0; a < 3; a++) {
          const acctChild = deriveCip1852(r, [1852, 1815, a]);
          const acctPub = bytesToHex(publicKeyFromScalar(acctChild.slice(0, 32)));
          process.stderr.write(`    acct ${a} pub: ${acctPub}\n`);
        }
      }
      process.stderr.write('\n');
      xsk = variants[0].raw; // fallback, will fail at match check below
    }
  } else {
    const cleaned = keyStr.replace(/[\s\r\n]+/g, '');
    process.stderr.write(`Input length: ${cleaned.length} chars\n`);

    if (/^[0-9a-fA-F]+$/.test(cleaned)) {
      xsk = hexToBytes(cleaned);
      process.stderr.write(`Key format: hex (${xsk.length} bytes)\n`);
    } else {
      const { bytes } = decodeBech32(cleaned);
      xsk = bytes;
      process.stderr.write(`Key format: bech32 (${bytes.length} bytes)\n`);
    }

    if (xsk.length === 64) {
      process.stderr.write('Got 64 bytes (kL||kR), padding with 32-byte zero chain code.\n');
      const padded = new Uint8Array(96);
      padded.set(xsk);
      xsk = padded;
    } else if (xsk.length > 96) {
      process.stderr.write(`Got ${xsk.length} bytes, using first 96 (kL||kR||cc).\n`);
      xsk = xsk.slice(0, 96);
    }
  }

  if (xsk.length !== 96) {
    process.stderr.write(`Error: expected 96 bytes for xprv, got ${xsk.length}\n`);
    process.exit(1);
  }

  process.stderr.write(`Target treasury key hash: ${TREASURY_KEY_HASH}\n`);
  process.stderr.write(`Body hash: ${BODY_HASH}\n\n`);

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

  // Patch the proposal with the new author
  const authorEntry = {
    name: AUTHOR_NAME,
    witness: {
      witnessAlgorithm: "ed25519",
      publicKey: pubHex,
      signature: sigHex
    }
  };

  proposal.authors = [...(proposal.authors || []), authorEntry];
  process.stdout.write(JSON.stringify(proposal, null, 2) + '\n');

  matchedXsk.fill(0);
  xsk.fill(0);

  process.stderr.write('Done. Key material cleared from memory.\n');
}

main().catch(err => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});
