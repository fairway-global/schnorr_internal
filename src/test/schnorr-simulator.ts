import {
  type CircuitContext,
  QueryContext,
  sampleContractAddress,
  constructorContext,
} from "@midnight-ntwrk/compact-runtime";

import {
  Contract,
  type Ledger,
  ledger,
  type Signature,
  type CredentialSubject,
  type SignedCredentialSubject,
} from "../managed/schnorr/contract/index.cjs";
import { type SchnorrPrivateState, witnesses } from "../witnesses.js";

import { hexToBytes, randomBytes } from "./utils.js";

// Fairway's company secret key - this is the ONLY key that can create valid signatures
export const FAIRWAY_SECRET_KEY = hexToBytes("1".repeat(64));

export class SchnorrSimulator {
  readonly contract: Contract<SchnorrPrivateState>;
  circuitContext: CircuitContext<SchnorrPrivateState>;

  constructor(secretKey: Uint8Array) {
    this.contract = new Contract<SchnorrPrivateState>(witnesses);
    const {
      currentPrivateState,
      currentContractState,
      currentZswapLocalState,
    } = this.contract.initialState(
      constructorContext({ secretKey }, "1".repeat(64)),
    );
    this.circuitContext = {
      currentPrivateState,
      currentZswapLocalState,
      originalState: currentContractState,
      transactionContext: new QueryContext(
        currentContractState.data,
        sampleContractAddress(),
      ),
    };
  }


  public getLedger(): Ledger {
    return ledger(this.circuitContext.transactionContext.state);
  }

  public getPrivateState(): SchnorrPrivateState {
    return this.circuitContext.currentPrivateState;
  }


  public derivePublicKey(): { x: bigint; y: bigint } {
    return this.contract.circuits.derive_pk(
      this.circuitContext,
      this.getPrivateState().secretKey,
    ).result;
  }

  public signMessage(message: string): Signature {
    const messageBytes = this.stringToBytes32(message);
    return this.contract.circuits.sign(
      this.circuitContext,
      messageBytes,
      this.getPrivateState().secretKey,
    ).result;
  }

  public verifySignature(message: string, signature: Signature): boolean {
    const messageBytes = this.stringToBytes32(message);
    
    try {
      // First check if the signature's public key matches our own public key
      // const ourPublicKey = this.derivePublicKey();
      // if (signature.pk.x !== ourPublicKey.x || signature.pk.y !== ourPublicKey.y) {
      //   return false; // Signature was created by a different key
      // }
      
      // Then verify the signature is mathematically valid
      this.contract.circuits.verify_signature(
        this.circuitContext,
        messageBytes,
        signature,
      );
      return true;
    } catch (error) {
      return false;
    }
  }


  public createCredentialSubject(
    id: string,
    firstName: string,
    lastName: string,
    nationalId: string,
    birthTimestamp: bigint
  ): CredentialSubject {
    return {
      id: this.stringToBytes32(id),
      first_name: this.stringToBytes32(firstName),
      last_name: this.stringToBytes32(lastName),
      national_identifier: this.stringToBytes32(nationalId),
      birth_timestamp: birthTimestamp,
    };
  }

  public hashCredentialSubject(credential: CredentialSubject): Uint8Array {
    return this.contract.circuits.subject_hash(
      this.circuitContext,
      credential,
    ).result;
  }

  public signCredentialSubject(credential: CredentialSubject): SignedCredentialSubject {
    const credentialHash = this.hashCredentialSubject(credential);
    const signature = this.contract.circuits.sign(
      this.circuitContext,
      credentialHash,
      this.getPrivateState().secretKey,
    ).result;
    
    return {
      subject: credential,
      signature,
    };
  }

  public verifySignedCredential(signedCredential: SignedCredentialSubject): boolean {
    try {
      const credentialHash = this.hashCredentialSubject(signedCredential.subject);
      this.contract.circuits.verify_signature(
        this.circuitContext,
        credentialHash,
        signedCredential.signature,
      );
      return true;
    } catch (error) {
      return false;
    }
  }

  public verifySignedCredentialWithPublicKey(
    signedCredential: SignedCredentialSubject,
    publicKey: { x: bigint; y: bigint }
  ): boolean {
    try {
      const credentialHash = this.hashCredentialSubject(signedCredential.subject);
      const modifiedSignature = {
        ...signedCredential.signature,
        pk: publicKey,
      };
      this.contract.circuits.verify_signature(
        this.circuitContext,
        credentialHash,
        modifiedSignature,
      );
      return true;
    } catch (error) {
      return false;
    }
  }

  public verifySignatureWithPublicKey(
    message: string,
    signature: Signature,
    publicKey: { x: bigint; y: bigint }
  ): boolean {
    try {
      const messageBytes = this.stringToBytes32(message);
      const modifiedSignature = {
        ...signature,
        pk: publicKey,
      };
      this.contract.circuits.verify_signature(
        this.circuitContext,
        messageBytes,
        modifiedSignature,
      );
      return true;
    } catch (error) {
      return false;
    }
  }


  public stringToBytes32(str: string): Uint8Array {
    const bytes = new Uint8Array(32);
    const strBytes = new TextEncoder().encode(str);
    bytes.set(strBytes.slice(0, Math.min(strBytes.length, 32)));
    return bytes;
  }
}