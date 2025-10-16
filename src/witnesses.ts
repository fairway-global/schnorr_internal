import { Ledger } from "./managed/schnorr/contract/index.cjs";
import { WitnessContext } from "@midnight-ntwrk/compact-runtime";

export type SchnorrPrivateState = {
  readonly secretKey: Uint8Array;
};

export const createSchnorrPrivateState = (secretKey: Uint8Array) => ({
  secretKey,
});

export const witnesses = {
  localSigningKey: ({
    privateState,
  }: WitnessContext<Ledger, SchnorrPrivateState>): [
    SchnorrPrivateState,
    Uint8Array,
  ] => [privateState, privateState.secretKey],
};