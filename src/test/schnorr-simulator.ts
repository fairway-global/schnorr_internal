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

import { FAIRWAY_SECRET_KEY, randomBytes } from "./utils.js";

// Fairway's company secret key - this is the ONLY key that can create valid signatures

export class SchnorrSimulator {
  // Shared contract instance across all simulators
  private static sharedContract: Contract<SchnorrPrivateState> | null = null;
  private static sharedLedgerState: any = null;
  private static sharedZswapState: any = null;

  readonly contract: Contract<SchnorrPrivateState>;
  circuitContext: CircuitContext<SchnorrPrivateState>;

  constructor(secretKey: Uint8Array) {
    // Initialize shared contract and ledger state on first instantiation
    if (!SchnorrSimulator.sharedContract) {
      SchnorrSimulator.sharedContract = new Contract<SchnorrPrivateState>(witnesses);
      
      // Initialize with Fairway's secret key to set fairway_pk in shared ledger
      const {
        currentPrivateState,
        currentContractState,
        currentZswapLocalState,
      } = SchnorrSimulator.sharedContract.initialState(
        constructorContext({ 
          localSigningKey: FAIRWAY_SECRET_KEY,
          signingNonce: randomBytes(32)
        }, "0".repeat(64)),
      );
      
      SchnorrSimulator.sharedLedgerState = currentContractState;
      SchnorrSimulator.sharedZswapState = currentZswapLocalState;
    }

    // All instances share the same contract
    this.contract = SchnorrSimulator.sharedContract;
    
    // Create instance-specific context with shared ledger state
    const localSigningKey = secretKey;
    this.circuitContext = {
      currentPrivateState: { 
        localSigningKey,
        signingNonce: randomBytes(32) // Fresh random nonce for each instance
      },
      currentZswapLocalState: SchnorrSimulator.sharedZswapState,
      originalState: SchnorrSimulator.sharedLedgerState,
      transactionContext: new QueryContext(
        SchnorrSimulator.sharedLedgerState.data,
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
      this.getPrivateState().localSigningKey,
    ).result;
  }

  public signMessage(message: string): Signature {
    const messageBytes = this.stringToBytes32(message);
    
    // Generate fresh random nonce for each signing operation
    const freshNonce = randomBytes(32);
    const contextWithFreshNonce = {
      ...this.circuitContext,
      currentPrivateState: {
        ...this.circuitContext.currentPrivateState,
        signingNonce: freshNonce // New random nonce each time!
      }
    };
    
    const result = this.contract.circuits.sign(
      contextWithFreshNonce,
      messageBytes,
    );
    
    // Update shared ledger state with new state from circuit execution
    SchnorrSimulator.sharedLedgerState = result.context.originalState;
    SchnorrSimulator.sharedZswapState = result.context.currentZswapLocalState;
    
    // Update this instance's context to use the new shared state
    this.circuitContext = result.context;
    
    return result.result;
  }

  public verifySignature(message: string, signature: Signature): boolean {
    const messageBytes = this.stringToBytes32(message);
    
    try {
      const result = this.contract.circuits.verify_signature(
        this.circuitContext,
        messageBytes,
        signature,
      );
      
      // Update shared ledger state with new state from circuit execution
      SchnorrSimulator.sharedLedgerState = result.context.originalState;
      SchnorrSimulator.sharedZswapState = result.context.currentZswapLocalState;
      
      // Update this instance's context to use the new shared state
      this.circuitContext = result.context;
      
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
    
    // Generate fresh random nonce for each signing operation
    const freshNonce = randomBytes(32);
    const contextWithFreshNonce = {
      ...this.circuitContext,
      currentPrivateState: {
        ...this.circuitContext.currentPrivateState,
        signingNonce: freshNonce
      }
    };
    
    const result = this.contract.circuits.sign(
      contextWithFreshNonce,
      credentialHash
    );
    
    // Update shared ledger state
    SchnorrSimulator.sharedLedgerState = result.context.originalState;
    SchnorrSimulator.sharedZswapState = result.context.currentZswapLocalState;
    
    // Update this instance's context
    this.circuitContext = result.context;
    
    return {
      subject: credential,
      signature: result.result,
      nonce: result.result.nonce as any, // The nonce from signature (Bytes<32>)
    };
  }

  public verifySignedCredential(signedCredential: SignedCredentialSubject): boolean {
    try {
      const credentialHash = this.hashCredentialSubject(signedCredential.subject);
      const result = this.contract.circuits.verify_signature(
        this.circuitContext,
        credentialHash,
        signedCredential.signature,
      );
      
      // Update shared ledger state with new state from circuit execution
      SchnorrSimulator.sharedLedgerState = result.context.originalState;
      SchnorrSimulator.sharedZswapState = result.context.currentZswapLocalState;
      
      // Update this instance's context to use the new shared state
      this.circuitContext = result.context;
      
      return true;
    } catch (error) {
      console.error("Verification error:", error);
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