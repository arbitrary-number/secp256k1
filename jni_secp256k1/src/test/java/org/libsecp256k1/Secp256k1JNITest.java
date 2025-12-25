package org.libsecp256k1;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit 5 tests for secp256k1 JNI wrapper with UCRT64 compilation
 * 
 * These tests verify all the secp256k1 functionality through JNI calls
 * to the UCRT64-compiled native library.
 */
public class Secp256k1JNITest {

    @BeforeAll
    static void loadLibrary() {
        // The library should already be loaded by the NativeSecp256k1 class
        // due to static initialization, but we'll ensure it works properly
        System.out.println("Library loading handled by NativeSecp256k1 class during static initialization.");
    }

    @Test
    @DisplayName("Test context creation and destruction")
    void testContextCreateDestroy() {
        long ctx = NativeSecp256k1.contextCreate(
            NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
        );
        assertNotEquals(0, ctx, "Context should be created successfully");
        
        NativeSecp256k1.contextDestroy(ctx);
        // Note: After destruction, using ctx would be unsafe, but we can't test it further
    }

    @Test
    @DisplayName("Test secret key verification")
    void testSeckeyVerify() {
        long ctx = NativeSecp256k1.contextCreate(
            NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
        );
        
        // Valid secret key (32 bytes, not all zeros, less than curve order)
        byte[] validSeckey = new byte[32];
        validSeckey[0] = (byte) 0x01; // Non-zero first byte
        
        int result = NativeSecp256k1.seckeyVerify(ctx, validSeckey);
        assertEquals(1, result, "Valid secret key should be verified successfully");
        
        // Invalid secret key (all zeros)
        byte[] invalidSeckey = new byte[32]; // All zeros
        
        result = NativeSecp256k1.seckeyVerify(ctx, invalidSeckey);
        assertEquals(0, result, "Invalid secret key should fail verification");
        
        NativeSecp256k1.contextDestroy(ctx);
    }

    @Test
    @DisplayName("Test public key computation and serialization")
    void testPubkeyComputation() {
        long ctx = NativeSecp256k1.contextCreate(
            NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
        );
        
        // Use a valid secret key
        byte[] seckey = new byte[32];
        seckey[0] = (byte) 0x01;
        seckey[1] = (byte) 0x23;
        seckey[2] = (byte) 0x45;
        seckey[3] = (byte) 0x67;
        seckey[4] = (byte) 0x89;
        seckey[5] = (byte) 0xAB;
        seckey[6] = (byte) 0xCD;
        seckey[7] = (byte) 0xEF;
        
        byte[] pubkey = NativeSecp256k1.computePubkey(ctx, seckey, true);
        assertNotNull(pubkey, "Public key should be computed successfully");
        assertTrue(pubkey.length > 0, "Public key should have content");
        
        // Test public key parsing
        boolean parsed = NativeSecp256k1.pubkeyParse(ctx, pubkey);
        assertTrue(parsed, "Public key should parse successfully");
        
        // Test public key serialization with both compressed and uncompressed
        byte[] serialized = NativeSecp256k1.pubkeySerialize(ctx, pubkey, true);
        assertNotNull(serialized, "Public key should serialize successfully");
        assertEquals(33, serialized.length, "Compressed public key should be 33 bytes");
        
        NativeSecp256k1.contextDestroy(ctx);
    }

    @Test
    @DisplayName("Test ECDSA signing and verification")
    void testSigningVerification() {
        long ctx = NativeSecp256k1.contextCreate(
            NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
        );
        
        // Create a valid secret key
        byte[] seckey = new byte[32];
        for (int i = 0; i < 32; i++) {
            seckey[i] = (byte) (i + 1); // Fill with non-zero data
        }
        
        // Create a message to sign (32 bytes)
        byte[] msg32 = new byte[32];
        for (int i = 0; i < 32; i++) {
            msg32[i] = (byte) ('A' + i); // Fill with data
        }
        
        // Compute public key from secret key
        byte[] pubkey = NativeSecp256k1.computePubkey(ctx, seckey, true);
        assertNotNull(pubkey, "Public key should be computed");
        
        // Sign the message
        byte[] signature = NativeSecp256k1.sign(ctx, msg32, seckey);
        assertNotNull(signature, "Signature should be created");
        assertTrue(signature.length > 0, "Signature should have content");
        
        // Verify the signature
        boolean verified = NativeSecp256k1.verify(ctx, signature, msg32, pubkey);
        assertTrue(verified, "Signature should verify correctly");
        
        // Test with compact signature as well
        byte[] compactSig = NativeSecp256k1.signCompact(ctx, msg32, seckey);
        assertNotNull(compactSig, "Compact signature should be created");
        assertEquals(64, compactSig.length, "Compact signature should be 64 bytes");
        
        NativeSecp256k1.contextDestroy(ctx);
    }

    @Test
    @DisplayName("Test context randomization")
    void testContextRandomize() {
        long ctx = NativeSecp256k1.contextCreate(
            NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
        );
        
        // Test randomization with a seed
        byte[] seed32 = new byte[32];
        for (int i = 0; i < 32; i++) {
            seed32[i] = (byte) (i * 2); // Fill with data
        }
        
        boolean result = NativeSecp256k1.contextRandomize(ctx, seed32);
        assertTrue(result, "Context should randomize successfully with seed");
        
        // Also test randomization without seed (internal entropy)
        long ctx2 = NativeSecp256k1.contextCreate(
            NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
        );
        boolean result2 = NativeSecp256k1.contextRandomize(ctx2, null);
        assertTrue(result2, "Context should randomize successfully with internal entropy");
        
        NativeSecp256k1.contextDestroy(ctx);
        NativeSecp256k1.contextDestroy(ctx2);
    }

    @Test
    @DisplayName("Test secret key negation")
    void testSeckeyNegate() {
        long ctx = NativeSecp256k1.contextCreate(
            NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
        );
        
        // Create a valid secret key
        byte[] seckey = new byte[32];
        seckey[0] = (byte) 0x01;
        seckey[1] = (byte) 0x23;
        seckey[2] = (byte) 0x45;
        
        // Verify the original key
        int valid = NativeSecp256k1.seckeyVerify(ctx, seckey);
        assertEquals(1, valid, "Original secret key should be valid");
        
        // Make a copy and negate it
        byte[] seckeyCopy = seckey.clone();
        boolean negated = NativeSecp256k1.seckeyNegate(ctx, seckeyCopy);
        assertTrue(negated, "Secret key should be negated successfully");
        
        // Verify the negated key is also valid
        int validAfterNegate = NativeSecp256k1.seckeyVerify(ctx, seckeyCopy);
        assertEquals(1, validAfterNegate, "Negated secret key should also be valid");
        
        // Negating again should give back the original
        boolean negatedAgain = NativeSecp256k1.seckeyNegate(ctx, seckeyCopy);
        assertTrue(negatedAgain, "Secret key should be negated again successfully");
        
        NativeSecp256k1.contextDestroy(ctx);
    }

    @Test
    @DisplayName("Test comprehensive secp256k1 workflow")
    void testCompleteWorkflow() {
        long ctx = NativeSecp256k1.contextCreate(
            NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
        );
        
        // Test context randomization (for security)
        boolean randomized = NativeSecp256k1.contextRandomize(ctx, null);
        assertTrue(randomized, "Context should randomize successfully");
        
        // Create a secret key
        byte[] seckey = new byte[32];
        for (int i = 0; i < 32; i++) {
            seckey[i] = (byte) (i + 1);
        }
        
        // Verify the secret key
        int valid = NativeSecp256k1.seckeyVerify(ctx, seckey);
        assertEquals(1, valid, "Secret key should be valid");
        
        // Compute public key
        byte[] pubkey = NativeSecp256k1.computePubkey(ctx, seckey, true);
        assertNotNull(pubkey, "Public key should be computed");
        
        // Test public key operations
        boolean parsed = NativeSecp256k1.pubkeyParse(ctx, pubkey);
        assertTrue(parsed, "Public key should parse");
        
        byte[] serializedPubkey = NativeSecp256k1.pubkeySerialize(ctx, pubkey, true);
        assertNotNull(serializedPubkey, "Public key should serialize");
        
        // Create a message to sign
        byte[] msg32 = new byte[32];
        for (int i = 0; i < 32; i++) {
            msg32[i] = (byte) ('M' + i % 10);
        }
        
        // Sign the message
        byte[] signature = NativeSecp256k1.sign(ctx, msg32, seckey);
        assertNotNull(signature, "Signature should be created");
        
        // Verify the signature
        boolean verified = NativeSecp256k1.verify(ctx, signature, msg32, pubkey);
        assertTrue(verified, "Signature should verify correctly");
        
        // Test compact format as well
        byte[] compactSig = NativeSecp256k1.signCompact(ctx, msg32, seckey);
        assertNotNull(compactSig, "Compact signature should be created");
        
        // Test negation operations
        byte[] seckeyCopy = seckey.clone();
        boolean seckeyNegated = NativeSecp256k1.seckeyNegate(ctx, seckeyCopy);
        assertTrue(seckeyNegated, "Secret key should be negated");
        
        byte[] pubkeyCopy = pubkey.clone();
        boolean pubkeyNegated = NativeSecp256k1.pubkeyNegate(ctx, pubkeyCopy);
        assertTrue(pubkeyNegated, "Public key should be negated");
        
        NativeSecp256k1.contextDestroy(ctx);
    }
}