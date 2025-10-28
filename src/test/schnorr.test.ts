import { SchnorrSimulator } from "./schnorr-simulator.js";
import {
  NetworkId,
  setNetworkId,
} from "@midnight-ntwrk/midnight-js-network-id";
import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { randomBytes, FAIRWAY_SECRET_KEY } from "./utils.js";

setNetworkId(NetworkId.Undeployed);

// Helper to suppress expected error messages in tests
const suppressConsoleErrors = () => {
  const originalConsoleError = console.error;
  beforeEach(() => {
    console.error = () => {}; // Suppress console.error during tests
  });
  afterEach(() => {
    console.error = originalConsoleError; // Restore after tests
  });
};

describe("Schnorr Signature Contract", () => {
  describe("Contract Initialization", () => {

    it("creates simulator with deterministic behavior", () => {

      const privateKey = randomBytes(32);

      const simulator1 = new SchnorrSimulator(privateKey);     
      const simulator2 = new SchnorrSimulator(privateKey);

      expect(simulator1.getPrivateState().localSigningKey).toEqual(simulator2.getPrivateState().localSigningKey);
      expect(simulator1.derivePublicKey()).toEqual(simulator2.derivePublicKey());
    });

    it("generates different public keys for different private keys", () => {
      const privateKey1 = randomBytes(32);
      const privateKey2 = randomBytes(32);
      
      const simulator1 = new SchnorrSimulator(privateKey1);
      const simulator2 = new SchnorrSimulator(privateKey2);
      
      expect(simulator1.derivePublicKey()).not.toEqual(simulator2.derivePublicKey());
    });
  });

  describe("Message Signing", () => {
    
    it("signs a simple message correctly", () => {
      const simulator = new SchnorrSimulator(randomBytes(32));
      const message = "Hello, Midnight Network!";
      
      const signature = simulator.signMessage(message);
      const signature1 = simulator.signMessage(message);
      const signature2 = simulator.signMessage(message);
      // console.log("Signature 1:", {
      //   pk: { x: signature1.pk.x.toString(16), y: signature1.pk.y.toString(16) },
      //   R: { x: signature1.R.x.toString(16), y: signature1.R.y.toString(16) },
      //   s: signature1.s.toString(16)
      // });
      // console.log("Signature 2:", {
      //   pk: { x: signature2.pk.x.toString(16), y: signature2.pk.y.toString(16) },
      //   R: { x: signature2.R.x.toString(16), y: signature2.R.y.toString(16) },
      //   s: signature2.s.toString(16)
      // });

      // Signatures may vary due to nonce randomness, but public keys should match
      expect(signature.pk).toEqual(signature1.pk);
  
      expect(signature).toBeDefined();
      expect(signature.pk).toBeDefined();
      expect(signature.R).toBeDefined();
      expect(signature.s).toBeDefined();
    });

    it("different signatures for same message with same signer (different nonces)", () => {
      const simulator = new SchnorrSimulator(randomBytes(32));
      const message = "Test message for different nonces";
      
      const signature1 = simulator.signMessage(message);
      const signature2 = simulator.signMessage(message);
      
      // Different nonces mean different signatures
      expect(signature1.s).not.toEqual(signature2.s);
      expect(signature1.R).not.toEqual(signature2.R);
      expect(signature1.nonce).not.toBe(signature2.nonce);
      // Public key should be the same
      expect(signature1.pk).toEqual(signature2.pk);
    });

    it("produces different signatures for different messages", () => {
      const simulator = new SchnorrSimulator(randomBytes(32));
      const message1 = "First message";
      const message2 = "Second message";
      
      const signature1 = simulator.signMessage(message1);
      // console.log("Signature 1:", {
      //   pk: { x: signature1.pk.x.toString(16), y: signature1.pk.y.toString(16) },
      //   R: { x: signature1.R.x.toString(16), y: signature1.R.y.toString(16) },
      //   s: signature1.s.toString(16)
      // });
      const signature2 = simulator.signMessage(message2);

      // console.log("Signature 2:", {
      //   pk: { x: signature2.pk.x.toString(16), y: signature2.pk.y.toString(16) },
      //   R: { x: signature2.R.x.toString(16), y: signature2.R.y.toString(16) },
      //   s: signature2.s.toString(16)
      // });
      
      expect(signature1.s).not.toEqual(signature2.s);
      expect(signature1.R).not.toEqual(signature2.R);
      // Public key should be the same
      expect(signature1.pk).toEqual(signature2.pk);
    });

    it("produces different signatures for same message with different keys", () => {
      const message = "Same message, different signers";
      
      const simulator1 = new SchnorrSimulator(randomBytes(32));
      const simulator2 = new SchnorrSimulator(randomBytes(32));
      
      const signature1 = simulator1.signMessage(message);
      // console.log("Signature 1:", {
      //   pk: { x: signature1.pk.x.toString(16), y: signature1.pk.y.toString(16) },
      //   R: { x: signature1.R.x.toString(16), y: signature1.R.y.toString(16) },
      //   s: signature1.s.toString(16)
      // });
      const signature2 = simulator2.signMessage(message);
      // console.log("Signature 2:", {
      //   pk: { x: signature2.pk.x.toString(16), y: signature2.pk.y.toString(16) },
      //   R: { x: signature2.R.x.toString(16), y: signature2.R.y.toString(16) },
      //   s: signature2.s.toString(16)
      // });
      
      expect(signature1.pk).not.toEqual(signature2.pk);
      expect(signature1.s).not.toEqual(signature2.s);
      expect(signature1.R).not.toEqual(signature2.R);
    });

    it("handles empty message", () => {
      const simulator = new SchnorrSimulator(randomBytes(32));
      const emptyMessage = "";
      
      const signature = simulator.signMessage(emptyMessage);
      
      expect(signature).toBeDefined();
      expect(signature.pk).toBeDefined();
    });

    it("handles long message ", () => {
      const simulator = new SchnorrSimulator(randomBytes(32));
      const longMessage = "This is a very long message that exceeds 32 bytes and should be truncated by the signing function";
      
      const signature = simulator.signMessage(longMessage);
      
      expect(signature).toBeDefined();
      expect(signature.pk).toBeDefined();
    });
  });


  describe("Signature Verification", () => {
    suppressConsoleErrors(); // Suppress expected verification errors
    
    it("verifies valid signature", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const message = "Verify this message";
      
      const signature = simulator.signMessage(message);
      const isValid = simulator.verifySignature(message, signature);
      
      //console.log("Is signature valid?", isValid);
      expect(isValid).toBe(true);
    });

    it("rejects signature signed with a different public key than fairway", () => {
      const simulator1 = new SchnorrSimulator(randomBytes(32));
      const simulator2 = new SchnorrSimulator(randomBytes(32));
      const message = "Test message";
      
      const signature1 = simulator1.signMessage(message);
      
      const isValid = simulator2.verifySignature(message, signature1);
      
      expect(isValid).toBe(false);
    });

    it("verifies multiple messages from same signer", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const messages = [
        "First message",
        "Second message", 
        "Third message"
      ];
      
      const signatures = messages.map(msg => simulator.signMessage(msg));
      
      signatures.forEach((sig, i) => {
        const isValid = simulator.verifySignature(messages[i], sig);
        expect(isValid).toBe(true);
      });
    });

  });

  describe("Credential Subject Operations", () => {
    suppressConsoleErrors(); // Suppress expected credential verification errors

    it("creates and hashes credential subject", () => {
      const simulator = new SchnorrSimulator(randomBytes(32));
      
      const credential = simulator.createCredentialSubject(
        "user-123",
        "Alice",
        "Johnson", 
        "ID987654321",
        BigInt(Date.now() - (25 * 365 * 24 * 60 * 60 * 1000)) // 25 years ago
      );
      
      const hash = simulator.hashCredentialSubject(credential);
      expect(hash).toBeDefined();
      expect(hash.length).toBe(32);
    });

    it("produces same hash for identical credentials", () => {
      const simulator = new SchnorrSimulator(randomBytes(32));
      
      const credential1 = simulator.createCredentialSubject(
        "user-456",
        "Bob",
        "Smith",
        "ID123456789", 
        BigInt(1000000000000) // Fixed timestamp
      );
      
      const credential2 = simulator.createCredentialSubject(
        "user-456",
        "Bob", 
        "Smith",
        "ID123456789",
        BigInt(1000000000000) // Same timestamp
      );
      
      const hash1 = simulator.hashCredentialSubject(credential1);
      const hash2 = simulator.hashCredentialSubject(credential2);
      
      expect(hash1).toEqual(hash2);
    });

    it("produces different hashes for different credentials", () => {
      const simulator = new SchnorrSimulator(randomBytes(32));
      
      const credential1 = simulator.createCredentialSubject(
        "user-111",
        "Alice",
        "Johnson",
        "ID111",
        BigInt(1000000000000)
      );
      
      const credential2 = simulator.createCredentialSubject(
        "user-222", 
        "Bob",
        "Smith",
        "ID222",
        BigInt(2000000000000)
      );
      
      const hash1 = simulator.hashCredentialSubject(credential1);
      const hash2 = simulator.hashCredentialSubject(credential2);
      
      expect(hash1).not.toEqual(hash2);
    });

    it("signs and verifies credential subject", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      
      const credential = simulator.createCredentialSubject(
        "user-789",
        "Charlie",
        "Brown",
        "ID789123456",
        BigInt(Date.now() - (30 * 365 * 24 * 60 * 60 * 1000)) // 30 years ago
      );
      
      const signedCredential = simulator.signCredentialSubject(credential);
      const isValid = simulator.verifySignedCredential(signedCredential);
      expect(isValid).toBe(true);
    });

    it("rejects tampered credential", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      
      const credential = simulator.createCredentialSubject(
        "user-abc",
        "David",
        "Wilson",
        "ID999888777",
        BigInt(Date.now() - (28 * 365 * 24 * 60 * 60 * 1000))
      );
      
      const signedCredential = simulator.signCredentialSubject(credential);
      
      // Tamper with the credential
      const tamperedCredential = {
        ...signedCredential,
        subject: {
          ...signedCredential.subject,
          first_name: simulator.stringToBytes32("Eve") // Changed name
        }
      };

      // console.log("Tampered Credential:", tamperedCredential);
      // console.log("Original Credential:", signedCredential);
      // console.log("Verifying original credential:", simulator.verifySignedCredential(signedCredential));
      // console.log("Verifying tampered credential:", simulator.verifySignedCredential(tamperedCredential));

      const isValid = simulator.verifySignedCredential(tamperedCredential);
      expect(isValid).toBe(false);
    });
  });

  // TODO
  describe("Performance and Edge Cases", () => {
    suppressConsoleErrors(); // Suppress expected errors for edge cases

    it("handles rapid consecutive signatures", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const messageCount = 10;
      
      const signatures = [];
      for (let i = 0; i < messageCount; i++) {
        const message = `Message ${i}`;
        const signature = simulator.signMessage(message);
        signatures.push({ message, signature });
      }
      
      // Verify all signatures
      signatures.forEach(({ message, signature }) => {
        const isValid = simulator.verifySignature(message, signature);
        expect(isValid).toBe(true);
      });
      
      expect(signatures.length).toBe(messageCount);
    });

    it("handles zero-filled private key edge case", () => {
      const zeroKey = new Uint8Array(32); // All zeros
      
      // This might throw or handle gracefully depending on implementation
      expect(() => {
        const simulator = new SchnorrSimulator(zeroKey);
        simulator.signMessage("Test with zero key");
      }).toThrow(); // Assuming implementation handles this gracefully
    });

    it("handles maximum value private key", () => {
      // Test that only Fairway key can create valid signatures
      // Non-Fairway keys should fail verification
      const maxKey = new Uint8Array(32);
      maxKey.fill(0xFF); // All 255s
      
      const nonFairwaySimulator = new SchnorrSimulator(maxKey);
      const signature = nonFairwaySimulator.signMessage("Test with max key");
      const isValid = nonFairwaySimulator.verifySignature("Test with max key", signature);
      
      // Should fail because signature pk won't match fairway_pk
      expect(isValid).toBe(false);
      
      // Now test with Fairway's key - should succeed
      const fairwaySimulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const fairwaySignature = fairwaySimulator.signMessage("Test with Fairway key");
      const fairwayValid = fairwaySimulator.verifySignature("Test with Fairway key", fairwaySignature);
      expect(fairwayValid).toBe(true);
    });

    it("maintains signature determinism", () => {
      const privateKey = randomBytes(32);
      const message = "Deterministic test message";
      
      const simulator1 = new SchnorrSimulator(privateKey);
      const simulator2 = new SchnorrSimulator(privateKey);
      
      const signature1 = simulator1.signMessage(message);
      const signature2 = simulator2.signMessage(message);
      
      // Note: Schnorr signatures might include randomness, so this test
      // depends on the implementation details
      expect(signature1.pk).toEqual(signature2.pk);
    });
  });

  describe("Integration Scenarios", () => {
    suppressConsoleErrors(); // Suppress expected verification errors
    
    it("simulates digital identity workflow with Fairway authority", () => {
      // In this system, only Fairway can issue valid credentials
      const fairwayIssuer = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      
      const credential = fairwayIssuer.createCredentialSubject(
        "user-integration-001",
        "Integration",
        "Tester",
        "ID-INT-001",
        BigInt(Date.now() - (22 * 365 * 24 * 60 * 60 * 1000))
      );
      
      const signedCredential = fairwayIssuer.signCredentialSubject(credential);
      
      // Any verifier can verify Fairway's signature
      const verifier = new SchnorrSimulator(randomBytes(32));
      const isCredentialValid = verifier.verifySignedCredential(signedCredential);
      
      expect(isCredentialValid).toBe(true);
    });

    it("handles digital identity issuance and verification workflow", () => {
      // Real-world scenario: Fairway issuing a verified credential
      const fairwayIssuer = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const student = new SchnorrSimulator(randomBytes(32));
      const verifier = new SchnorrSimulator(randomBytes(32));
      
      // Step 1: Create a realistic credential
      const credentialSubject = fairwayIssuer.createCredentialSubject(
        "student123",
        "John",
        "Doe", 
        "ID12345",
        1700000000n // Birth timestamp
      );
      
      // Step 2: Fairway signs the credential
      const issuedCredential = fairwayIssuer.signCredentialSubject(credentialSubject);
      
      // Step 3: Student verifies the credential
      const studentVerification = student.verifySignedCredential(issuedCredential);
      expect(studentVerification).toBe(true);
      
      // Step 4: Employer (verifier) independently verifies the credential
      const employerVerification = verifier.verifySignedCredential(issuedCredential);
      expect(employerVerification).toBe(true);
      
      // Step 5: Test failure case - tampered credential should fail
      const tamperedCredential = {
        ...issuedCredential,
        subject: {
          ...issuedCredential.subject,
          first_name: verifier.stringToBytes32("Fake")
        }
      };
      
      const tamperedVerification = verifier.verifySignedCredential(tamperedCredential);
      expect(tamperedVerification).toBe(false);
    });

    it("handles multi-party contract signing scenario with Fairway authority", () => {
      // Real-world scenario: Fairway certifies agreements
      const parties = [
        { name: "Alice Corp", key: randomBytes(32), role: "Contractor" },
        { name: "Bob Industries", key: randomBytes(32), role: "Client" },
        { name: "Charlie Legal", key: randomBytes(32), role: "Legal Witness" }
      ];
      
      const contractTerms = `
        SERVICE AGREEMENT
        Date: 2024-12-15
        Parties: Alice Corp (Contractor), Bob Industries (Client), Charlie Legal (Witness)
        Terms: Development of blockchain application for $100,000
        Duration: 6 months starting 2025-01-01
        Payment: 50% upfront, 50% on completion
        All parties agree to these terms and conditions.
      `.trim();
      
      // Fairway signs the contract agreement
      const fairway = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const contractSignature = fairway.signMessage(contractTerms);
      
      
      // Independent verification by external auditor
      const auditor = new SchnorrSimulator(randomBytes(32));
      const isValid = auditor.verifySignature(contractTerms, contractSignature);
      
      expect(isValid).toBe(true);
      
      // Test failure case - modified contract should fail verification
      const completelyDifferentContract = "This is a completely different contract with different terms";
      const differentVerification = auditor.verifySignature(
        completelyDifferentContract,
        contractSignature
      );
      expect(differentVerification).toBe(false);
    });

    it("handles credential revocation and reissuance workflow", () => {
      // Real-world scenario: Fairway issues and renews licenses
      const authority = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const citizen = new SchnorrSimulator(randomBytes(32));
      const verifier = new SchnorrSimulator(randomBytes(32));
      
      // Initial license issuance
      const originalLicense = authority.createCredentialSubject(
        "license456",
        "Jane",
        "Smith",
        "DL789",
        1600000000n // Birth timestamp
      );
      
      const originalCredential = authority.signCredentialSubject(originalLicense);
      
      // License renewal with updated information
      const renewedLicense = authority.createCredentialSubject(
        "license456-renewed",
        "Jane",
        "Smith",
        "DL789-NEW",
        1600000000n // Same birth timestamp
      );
      
      const renewedCredential = authority.signCredentialSubject(renewedLicense);
      
      // Signatures should have different nonces
      expect(originalCredential.signature.nonce).not.toBe(renewedCredential.signature.nonce);
      
      // Verify original license is valid
      const originalVerification = verifier.verifySignedCredential(originalCredential);
      expect(originalVerification).toBe(true);
      
      // Verify renewed license is valid
      const renewedVerification = verifier.verifySignedCredential(renewedCredential);
      expect(renewedVerification).toBe(true);
      
      // Both credentials were successfully verified
      expect(originalVerification).toBe(true);
      expect(renewedVerification).toBe(true);
      
      // Replay attack prevention: trying to verify original credential again fails
      const replayAttempt = verifier.verifySignedCredential(originalCredential);
      expect(replayAttempt).toBe(false);
    });
  });

  describe("Replay Attack Prevention", () => {
    suppressConsoleErrors(); // Suppress expected replay attack errors
    
    it("should prevent replaying the same signature twice", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const message = "transfer 100 tokens";
      
      const signature = simulator.signMessage(message);
      
      // First verification should succeed
      const firstVerify = simulator.verifySignature(message, signature);
      expect(firstVerify).toBe(true);
      
      // Attempting to verify the same signature again should fail (replay attack)
      const secondVerify = simulator.verifySignature(message, signature);
      expect(secondVerify).toBe(false);
    });

    it("should allow signing the same message multiple times with different nonces", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const message = "transfer 100 tokens";
      
      // Sign the same message three times
      const sig1 = simulator.signMessage(message);
      const sig2 = simulator.signMessage(message);
      const sig3 = simulator.signMessage(message);
      
      // Each signature should have a different nonce
      expect(sig1.nonce).not.toBe(sig2.nonce);
      expect(sig2.nonce).not.toBe(sig3.nonce);
      expect(sig1.nonce).not.toBe(sig3.nonce);
      
      // Each signature should be different
      expect(sig1.s).not.toBe(sig2.s);
      expect(sig1.R).not.toEqual(sig2.R);
      
      // All verifications should succeed (different nonces)
      expect(simulator.verifySignature(message, sig1)).toBe(true);
      expect(simulator.verifySignature(message, sig2)).toBe(true);
      expect(simulator.verifySignature(message, sig3)).toBe(true);
      
      // But replaying any of them should fail
      expect(simulator.verifySignature(message, sig1)).toBe(false);
      expect(simulator.verifySignature(message, sig2)).toBe(false);
      expect(simulator.verifySignature(message, sig3)).toBe(false);
    });

    it("should increment nonce sequentially", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const messages = ["msg1", "msg2", "msg3", "msg4", "msg5"];
      const signatures = [];
      
      // Sign multiple messages
      for (const msg of messages) {
        signatures.push(simulator.signMessage(msg));
      }
      
      // Check nonces are sequential
      for (let i = 0; i < signatures.length; i++) {
        if (i > 0) {
          expect(Number(signatures[i].nonce)).toBe(Number(signatures[i-1].nonce) + 1);
        }
      }
    });

    it("should allow verifying signatures in any order", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      
      // Sign multiple different messages
      const sig1 = simulator.signMessage("msg1");
      const sig2 = simulator.signMessage("msg2");
      const sig3 = simulator.signMessage("msg3");
      
      // Verify in reverse order (should all succeed)
      expect(simulator.verifySignature("msg3", sig3)).toBe(true);
      expect(simulator.verifySignature("msg1", sig1)).toBe(true);
      expect(simulator.verifySignature("msg2", sig2)).toBe(true);
    });

    it("should prevent double-spending attack", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const transferMessage = "transfer 1000 tokens to Bob";
      
      // User creates a transfer signature
      const signature = simulator.signMessage(transferMessage);
      
      // First transfer succeeds
      expect(simulator.verifySignature(transferMessage, signature)).toBe(true);
      
      // Attacker tries to replay the signature (should fail)
      expect(simulator.verifySignature(transferMessage, signature)).toBe(false);
      
      // Multiple replay attempts all fail
      for (let i = 0; i < 5; i++) {
        expect(simulator.verifySignature(transferMessage, signature)).toBe(false);
      }
    });

    it("should prevent replay of old signatures after many new ones", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      
      // Create an old signature
      const oldMessage = "old transaction";
      const oldSignature = simulator.signMessage(oldMessage);
      
      // Verify it once
      expect(simulator.verifySignature(oldMessage, oldSignature)).toBe(true);
      
      // Create and verify many new signatures
      for (let i = 0; i < 50; i++) {
        const sig = simulator.signMessage(`transaction ${i}`);
        simulator.verifySignature(`transaction ${i}`, sig);
      }
      
      // Try to replay the old signature (should fail - nonce already used)
      expect(simulator.verifySignature(oldMessage, oldSignature)).toBe(false);
    });

    it("should ensure each signature gets a unique nonce", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const nonces = new Set();
      const numSignatures = 30;
      
      for (let i = 0; i < numSignatures; i++) {
        const sig = simulator.signMessage(`message ${i}`);
        
        // Check this nonce hasn't been used before
        expect(nonces.has(sig.nonce)).toBe(false);
        
        nonces.add(sig.nonce);
      }
      
      // All nonces should be unique
      expect(nonces.size).toBe(numSignatures);
    });

    it("should bind nonce to message content", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const msg1 = "message A";
      const msg2 = "message B";
      
      const sig1 = simulator.signMessage(msg1);
      const sig2 = simulator.signMessage(msg2);
      
      // Different messages should have different nonces
      expect(sig1.nonce).not.toBe(sig2.nonce);
      
      // Correct message verifies
      expect(simulator.verifySignature(msg1, sig1)).toBe(true);
      
      // Wrong message fails (even though signature is valid)
      expect(simulator.verifySignature(msg1, sig2)).toBe(false);
      
      // Second signature verifies with correct message
      expect(simulator.verifySignature(msg2, sig2)).toBe(true);
    });

    it("should prevent replay of credential signatures", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const credential = simulator.createCredentialSubject(
        "user123",
        "John",
        "Doe",
        "SSN-123-45-6789",
        BigInt(Date.now())
      );
      
      const signedCredential = simulator.signCredentialSubject(credential);
      
      // First verification succeeds
      expect(simulator.verifySignedCredential(signedCredential)).toBe(true);
      
      // Replay should fail
      expect(simulator.verifySignedCredential(signedCredential)).toBe(false);
    });

    it("should handle concurrent signing with unique nonces", () => {
      const simulator = new SchnorrSimulator(FAIRWAY_SECRET_KEY);
      const message = "concurrent transaction";
      const signatures = [];
      
      // Sign the same message 10 times rapidly
      for (let i = 0; i < 10; i++) {
        signatures.push(simulator.signMessage(message));
      }
      
      // Each signature should have a unique nonce
      const nonces = signatures.map(sig => sig.nonce);
      console.log("Raw nonces:", nonces.map(n => Array.from(n).slice(0, 8))); // First 8 bytes of each nonce
      
      const nonceHashes = signatures.map(sig => Array.from(sig.nonce).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16));
      console.log("Nonce hashes (first 16 hex chars):", nonceHashes);
      
      const uniqueNonces = new Set(nonceHashes);
      expect(uniqueNonces.size).toBe(10);
      
      // All signatures should verify successfully (first time)
      for (let i = 0; i < signatures.length; i++) {
        expect(simulator.verifySignature(message, signatures[i])).toBe(true);
      }
      
      // None should verify a second time
      for (let i = 0; i < signatures.length; i++) {
        expect(simulator.verifySignature(message, signatures[i])).toBe(false);
      }
    });
  });
});

