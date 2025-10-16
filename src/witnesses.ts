import { Ledger } from "./managed/schnorr/contract/index.cjs";
import { WitnessContext } from "@midnight-ntwrk/compact-runtime";

export type SchnorrPrivateState = {
  readonly localSigningKey: Uint8Array;
};

export const createSchnorrPrivateState = (localSigningKey: Uint8Array) => ({
  localSigningKey,
});

export const witnesses = {
  localSigningKey: ({
    privateState,
  }: WitnessContext<Ledger, SchnorrPrivateState>): [
    SchnorrPrivateState,
    Uint8Array,
  ] => [privateState, privateState.localSigningKey],
};