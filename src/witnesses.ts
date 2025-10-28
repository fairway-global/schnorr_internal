import { Ledger } from "./managed/schnorr/contract/index.cjs";
import { WitnessContext } from "@midnight-ntwrk/compact-runtime";

export const randomBytes = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
};


export type SchnorrPrivateState = {
  readonly localSigningKey: Uint8Array;
  readonly signingNonce: Uint8Array;
};

export const createSchnorrPrivateState = (localSigningKey: Uint8Array, signingNonce: Uint8Array) => ({
  localSigningKey,
  signingNonce
});

export const witnesses = {
  localSigningKey: ({
    privateState,
  }: WitnessContext<Ledger, SchnorrPrivateState>): [
    SchnorrPrivateState,
    Uint8Array,
  ] => [privateState, privateState.localSigningKey],
  signingNonce: ({
    privateState,
  }: WitnessContext<Ledger, SchnorrPrivateState>): [
    SchnorrPrivateState,
    Uint8Array,
  ] => {
    // Generate a random bigint and convert to 32-byte array
    const randomBigInt = BigInt('0x' + Array.from(randomBytes(32))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(''));
    
    // Convert bigint back to 32-byte Uint8Array
    const hex = randomBigInt.toString(16).padStart(64, '0');
    const generatedNonce = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      generatedNonce[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    
    return [privateState, generatedNonce];
  },
};