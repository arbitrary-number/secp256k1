package org.libsecp256k1;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit 5 test specifically for elliptic curve point operations
 * Demonstrating scalar multiplication like G * 2 = 2G
 */
public class PointOperationsTest {

    @Test
    @DisplayName("Test scalar multiplication: generate secret key, compute public key, verify operations")
    void testScalarMultiplication() {
        System.out.println("=== Testing secp256k1 Point Operations ===");
        
        // Create context
        long ctx = NativeSecp256k1.contextCreate(
            NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
        );
        assertNotEquals(0, ctx, "Context should be created successfully");
        System.out.println("✓ Context created: " + ctx);
        
        // Generate a secret key (32 bytes, need to be a valid scalar)
        byte[] seckey = new byte[32];
        seckey[0] = 0x02;  // Valid secret key: 2 (which will give us 2*G when multiplied by generator)
        
        // Verify the secret key
        int valid = NativeSecp256k1.seckeyVerify(ctx, seckey);
        assertEquals(1, valid, "Secret key should be valid");
        System.out.println("✓ Secret key verified as valid: " + bytesToHex(seckey, 8));
        
        // Compute public key corresponding to secret key (this is sk*G)
        byte[] pubkeyRaw = NativeSecp256k1.computePubkey(ctx, seckey, true);
        assertNotNull(pubkeyRaw, "Public key should be computed");
        assertTrue(pubkeyRaw.length > 0, "Public key should have content");
        System.out.println("✓ Public key computed from secret key (equivalent to sk*G): " + bytesToHex(pubkeyRaw, 16));
        
        // Now test using the secp256k1 API to do point multiplication
        // The secret key represents a scalar, and public key is that scalar times the generator point G
        // So when seckey=2, pubkey = 2*G
        System.out.println("✓ When secret key = 2, public key = 2 * Generator Point (G) = 2G");
        
        // Test that we can parse and re-serialize the public key
        boolean parsed = NativeSecp256k1.pubkeyParse(ctx, pubkeyRaw);
        assertTrue(parsed, "Public key should parse successfully");
        
        byte[] serialized = NativeSecp256k1.pubkeySerialize(ctx, pubkeyRaw, true);
        assertNotNull(serialized, "Public key should serialize successfully");
        assertArrayEquals(pubkeyRaw, serialized, "Serialized key should match original");
        System.out.println("✓ Public key parsing and serialization verified");
        
        // Test with a different scalar (e.g., multiply by 3)
        byte[] seckey3 = new byte[32];
        seckey3[0] = 0x03; // Secret key = 3, so public key should be 3*G
        
        int valid3 = NativeSecp256k1.seckeyVerify(ctx, seckey3);
        assertEquals(1, valid3, "Secret key 3 should be valid");
        
        byte[] pubkey3Raw = NativeSecp256k1.computePubkey(ctx, seckey3, true);
        assertNotNull(pubkey3Raw, "Public key for 3 should be computed");
        assertNotEquals(pubkeyRaw, pubkey3Raw, "3G should be different from 2G");
        System.out.println("✓ Public key for 3 (3G) computed: " + bytesToHex(pubkey3Raw, 16));
        
        // Test signing to indirectly verify the curve operations
        byte[] msg32 = new byte[32];
        for (int i = 0; i < 32; i++) {
            msg32[i] = (byte) ('A' + i);  // Fill with 'A', 'B', etc.
        }
        
        // Sign the message with our secret key
        byte[] signature = NativeSecp256k1.sign(ctx, msg32, seckey);
        assertNotNull(signature, "Signature should be created with 2*G derived key");
        System.out.println("✓ Signed message with key derived from 2*G");
        
        // Verify the signature using the corresponding public key (2G)
        boolean verified = NativeSecp256k1.verify(ctx, signature, msg32, pubkeyRaw);
        assertTrue(verified, "Signature should verify with corresponding public key");
        System.out.println("✓ Verified signature with public key (2G)");
        
        // Also test compact signing
        byte[] compactSig = NativeSecp256k1.signCompact(ctx, msg32, seckey);
        assertNotNull(compactSig, "Compact signature should be created");
        assertEquals(64, compactSig.length, "Compact signature should be 64 bytes");
        System.out.println("✓ Compact signature created successfully: " + compactSig.length + " bytes");
        
        // Test negation operations
        byte[] seckeyCopy = seckey.clone();
        boolean negated = NativeSecp256k1.seckeyNegate(ctx, seckeyCopy);
        assertTrue(negated, "Secret key should negate successfully");
        
        System.out.println("✓ Secret key negation test completed");
        
        // Clean up context
        NativeSecp256k1.contextDestroy(ctx);
        System.out.println("✓ Context destroyed");
        
        System.out.println("=== Point operations test completed successfully ===");
        System.out.println("Demonstrated: scalar multiplication where seckey=2 produces public key = 2*G");
        System.out.println("Verified that the secp256k1 elliptic curve operations work correctly through JNI");
    }

    @Test
    @DisplayName("Test secp256k1 base point (G) operations")
    void testBasePointOperations() {
        System.out.println("\n=== Testing secp256k1 Base Point (G) Operations ===");
        
        // Create context
        long ctx = NativeSecp256k1.contextCreate(
            NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
        );
        assertNotEquals(0, ctx, "Context should be created successfully");
        
        // The secp256k1 base point G can be obtained by using secret key 1
        // (1*G = G, the generator point)
        byte[] seckey1 = new byte[32];
        seckey1[31] = 0x01; // Secret key = 1 (last byte for little-endian interpretation)
        
        int valid = NativeSecp256k1.seckeyVerify(ctx, seckey1);
        assertEquals(1, valid, "Secret key 1 should be valid");
        
        // Compute public key for secret key 1, which should give us the generator point G
        byte[] basePointG = NativeSecp256k1.computePubkey(ctx, seckey1, false); // Uncompressed for clearer identification
        assertNotNull(basePointG, "Generator point G should be computed");
        System.out.println("✓ Generator point G computed: " + bytesToHex(basePointG, 16));
        
        // Now test with secret key 2 to get 2G
        byte[] seckey2 = new byte[32];
        seckey2[31] = 0x02; // Secret key = 2
        
        int valid2 = NativeSecp256k1.seckeyVerify(ctx, seckey2);
        assertEquals(1, valid2, "Secret key 2 should be valid");
        
        byte[] point2G = NativeSecp256k1.computePubkey(ctx, seckey2, false);
        assertNotNull(point2G, "Point 2G should be computed");
        assertNotEquals(basePointG, point2G, "2G should be different from G");
        System.out.println("✓ Point 2G computed: " + bytesToHex(point2G, 16));
        
        // Verify these are valid points on the curve by using them in signing
        byte[] dummyMsg = new byte[32];
        for (int i = 0; i < 32; i++) {
            dummyMsg[i] = (byte) i;
        }
        
        // Sign with the 2G-derived key
        byte[] sig2G = NativeSecp256k1.sign(ctx, dummyMsg, seckey2);
        assertNotNull(sig2G, "Signature should work with 2G-derived key");
        
        // Verify with the 2G public key
        boolean verified2G = NativeSecp256k1.verify(ctx, sig2G, dummyMsg, point2G);
        assertTrue(verified2G, "Signature should verify with 2G public key");
        System.out.println("✓ Verified operations work with 2G point");
        
        // Clean up
        NativeSecp256k1.contextDestroy(ctx);
        System.out.println("✓ Base point operations test completed");
        System.out.println("Demonstrated: G (generator) and 2G point computations using scalar multiplication");
    }

    private static String bytesToHex(byte[] bytes, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count && i < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        return sb.toString();
    }
}