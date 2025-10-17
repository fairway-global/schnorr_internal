import { Ledger } from "./managed/schnorr/contract/index.cjs";
import { WitnessContext } from "@midnight-ntwrk/compact-runtime";

export const randomBytes = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
};


export type SchnorrPrivateState = {
  readonly localSigningKey: Uint8Array;
  readonly sigingNoce: Uint8Array;
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
    const  genenratedNonce = randomBytes(32);
    return [privateState, genenratedNonce];
  },
};