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
  pureCircuits,
} from "../managed/schnorr/contract/index.cjs";
import { type PrivateState, witnesses } from "../witnesses.js";


// Schnorr signature types
export type SchnorrSignature = {
  pk: any; // CurvePoint
  R: any;  // CurvePoint
  s: any;  // Field
};

export type CredentialSubject = {
  id: Uint8Array;
  first_name: Uint8Array;
  last_name: Uint8Array;
  national_identifier: Uint8Array;
  birth_timestamp: bigint;
};

export type SignedCredentialSubject = {
  subject: CredentialSubject;
  signature: SchnorrSignature;
};

export class SchnorrSimulator {
  private privateKey: Uint8Array;
  private publicKey: any;
  private contract: Contract<{ secretKey: Uint8Array }, typeof witnesses>;
  private currentLedger: Ledger;
  private currentPrivateState: PrivateState = { privateState: 0 };

  /** */

  constructor(privateKey: Uint8Array) {
    this.privateKey = privateKey;
    this.contract = new Contract(witnesses);

    try {

      /** */
      const constructorCtx = constructorContext({ privateCounter: 0 }, "0".repeat(64));
      const initialResult = this.contract.initialState(constructorCtx);
      
      // Fix: Use currentContractState instead of newState
      this.currentLedger = ledger(initialResult.currentContractState);
      console.log("Ledger created successfully");
    } catch (error) {
      console.warn("Using fallback initialization for testing:", error);  
      this.currentLedger = {
        sequence: 0n,
        data: new Uint8Array(32)
      } as any;
    }

    this.publicKey = this.derivePublicKey();
  }

  getPrivateKey(): Uint8Array {
    return this.privateKey;
  }

  getHash(input: bigint ): Uint8Array {
    // Use the real cryptographic hashing circuit
    return pureCircuits.hash_field_to_bytes32(input);
  }

  getLedger(): Ledger {
    return this.currentLedger;
  }

  public getPrivateState(): PrivateState{
    return this.currentPrivateState;
  }
  derivePublicKey(): { x: bigint; y: bigint } {
    // Use the real cryptographic circuit to derive public key
    return pureCircuits.derive_pk(this.privateKey);
  }

  signMessage(message: string): SchnorrSignature {
    const messageBytes = this.stringToBytes32(message);
    
    // Use the real Schnorr signing circuit
    return pureCircuits.sign(messageBytes, this.privateKey);
  }

  verifySignature(message: string, signature: SchnorrSignature): boolean {
    const messageBytes = this.stringToBytes32(message);
    
    try {
      // First, check if the signature was created by this simulator (same public key)
      const myPublicKey = this.derivePublicKey();
      
      // Check if the signature's embedded public key matches our public key
      if (signature.pk.x !== myPublicKey.x || signature.pk.y !== myPublicKey.y) {
        // Signature was created by a different entity, should reject
        return false;
      }
      
      // If public keys match, verify the signature mathematically
      pureCircuits.verify_signature(messageBytes, signature);
      return true; // If no error thrown, verification succeeded
    } catch (error) {
      // Debug: Log what's failing
      console.log("Verification failed:", error instanceof Error ? error.message : String(error));
      console.log("Message bytes:", Array.from(messageBytes).slice(0, 8).map(b => b.toString(16)).join(''));
      console.log("Signature pk:", signature.pk);
      console.log("Signature R:", signature.R);
      console.log("Signature s:", signature.s.toString(16));
      // If verification fails, the circuit throws an error
      return false;
    }
  }

  verifySignatureWithPublicKey(message: string, signature: SchnorrSignature, publicKey: { x: bigint; y: bigint }): boolean {
    try {
      const messageBytes = this.stringToBytes32(message);
      
      // Create a modified signature with the provided public key
      const modifiedSignature = {
        ...signature,
        pk: publicKey  // Use the provided public key instead of the one in signature
      };
      
      // Use the real Schnorr verification circuit with the provided public key
      // The verify_signature circuit throws if verification fails, returns void if success
      pureCircuits.verify_signature(messageBytes, modifiedSignature);
      return true; // If no error thrown, verification succeeded
    } catch (error) {
      return false; // If error thrown, signature is invalid
    }
  }

  createCredentialSubject(
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
      birth_timestamp: birthTimestamp
    };
  }

  hashCredentialSubject(credential: CredentialSubject): Uint8Array {
    // Use the real cryptographic hashing circuit
    return pureCircuits.subject_hash(credential);
  }

  signCredentialSubject(credential: CredentialSubject): SignedCredentialSubject {
    // Use real cryptographic operations - no fallback
    const credentialHash = this.hashCredentialSubject(credential);
    const signature = pureCircuits.sign(credentialHash, this.privateKey);
    
    return {
      subject: credential,
      signature
    };
  }

  verifySignedCredential(signedCredential: SignedCredentialSubject): boolean {
    try {
      // Use real cryptographic verification - no fallback
      const credentialHash = this.hashCredentialSubject(signedCredential.subject);
      pureCircuits.verify_signature(credentialHash, signedCredential.signature);
      return true; // If no error thrown, verification succeeded
    } catch (error) {
      // If verification fails, the circuit throws an error
      return false;
    }
  }

  verifySignedCredentialWithPublicKey(signedCredential: SignedCredentialSubject, publicKey: { x: bigint; y: bigint }): boolean {
    try {
      const credentialHash = this.hashCredentialSubject(signedCredential.subject);
      
      // Create modified signature with provided public key
      const modifiedSignature = {
        ...signedCredential.signature,
        pk: publicKey
      };
      
      // Use the real Schnorr verification circuit with the provided public key
      // The verify_signature circuit throws if verification fails, returns void if success
      pureCircuits.verify_signature(credentialHash, modifiedSignature);
      return true; // If no error thrown, verification succeeded
    } catch (error) {
      return false; // If error thrown, verification failed
    }
  }

  stringToBytes32(str: string): Uint8Array {
    const bytes = new Uint8Array(32);
    const strBytes = new TextEncoder().encode(str);
    bytes.set(strBytes.slice(0, Math.min(strBytes.length, 32)));
    return bytes;
  }

  // Utility methods for testing
  switchUser(newPrivateKey: Uint8Array): void {
    this.privateKey = newPrivateKey;
    this.publicKey = this.derivePublicKey();
  }

  // Generate test signatures for performance testing
  generateTestSignatures(count: number): Array<{ message: string; signature: SchnorrSignature }> {
    const results: Array<{ message: string; signature: SchnorrSignature }> = [];
    
    for (let i = 0; i < count; i++) {
      const message = `Test message ${i + 1}`;
      const signature = this.signMessage(message);
      results.push({ message, signature });
    }
    
    return results;
  }

  // Batch verify signatures
  verifySignatureBatch(signatures: Array<{ message: string; signature: SchnorrSignature }>): boolean[] {
    return signatures.map(({ message, signature }) => {
      try {
        return this.verifySignature(message, signature);
      } catch {
        return false;
      }
    });
  }

  // Create test credential with random data
  createTestCredential(suffix: string = ""): CredentialSubject {
    const timestamp = BigInt(Date.now() - Math.floor(Math.random() * 50 * 365 * 24 * 60 * 60 * 1000));
    
    return this.createCredentialSubject(
      `test-id-${Math.random().toString(36).substr(2, 9)}${suffix}`,
      `TestFirst${suffix}`,
      `TestLast${suffix}`,
      `ID${Math.random().toString().substr(2, 9)}${suffix}`,
      timestamp
    );
  }

  // Performance measurement helper
  measureSigningPerformance(messageCount: number): {
    signingTime: number;
    verificationTime: number;
    averageSignTime: number;
    averageVerifyTime: number;
  } {
    const messages = Array.from({ length: messageCount }, (_, i) => `Performance test message ${i}`);
    
    // Measure signing time
    const signStart = Date.now();
    const signatures = messages.map(msg => this.signMessage(msg));
    const signingTime = Date.now() - signStart;
    
    // Measure verification time
    const verifyStart = Date.now();
    signatures.forEach((sig, i) => {
      this.verifySignature(messages[i], sig);
    });
    const verificationTime = Date.now() - verifyStart;
    
    return {
      signingTime,
      verificationTime,
      averageSignTime: signingTime / messageCount,
      averageVerifyTime: verificationTime / messageCount
    };
  }

  // Digital identity simulation
  simulateDigitalIdentityWorkflow(): {
    credential: SignedCredentialSubject;
    messageSignature: { message: string; signature: SchnorrSignature };
    verificationResults: { credentialValid: boolean; messageValid: boolean };
  } {
    // Create a digital identity credential
    const credential = this.createCredentialSubject(
      "digital-id-001",
      "John",
      "Doe",
      "DID123456789",
      BigInt(Date.now() - (30 * 365 * 24 * 60 * 60 * 1000)) // 30 years old
    );

    // Sign the credential
    const signedCredential = this.signCredentialSubject(credential);

    // Sign a message with the identity
    const message = "I hereby consent to the terms of service";
    const messageSignature = this.signMessage(message);

    // Verify both
    const credentialValid = this.verifySignedCredential(signedCredential);
    const messageValid = this.verifySignature(message, messageSignature);

    return {
      credential: signedCredential,
      messageSignature: { message, signature: messageSignature },
      verificationResults: { credentialValid, messageValid }
    };
  }
}
