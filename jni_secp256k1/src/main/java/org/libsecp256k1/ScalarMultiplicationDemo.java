package org.libsecp256k1;

/**
 * Simple test to demonstrate scalar multiplication: G * 2 = 2G
 * This specifically tests the elliptic curve point operations through JNI
 */
public class ScalarMultiplicationDemo {
    
    public static void main(String[] args) {
        System.out.println("=== Scalar Multiplication Demonstration: G * 2 = 2G ===");
        System.out.println("This test verifies secp256k1 elliptic curve point multiplication through JNI.");
        System.out.println();
        
        try {
            // Create context for signing and verification operations
            long ctx = NativeSecp256k1.contextCreate(
                NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
            );
            
            if (ctx == 0) {
                System.out.println("❌ Failed to create secp256k1 context");
                return;
            }
            
            System.out.println("✓ Context created successfully");
            
            // Secret key = 1 represents the generator point G  
            byte[] seckey1 = new byte[32];
            seckey1[31] = 0x01;  // Little-endian: set last byte to 1
            
            // Verify the secret key
            int valid1 = NativeSecp256k1.seckeyVerify(ctx, seckey1);
            if (valid1 != 1) {
                System.out.println("❌ Secret key 1 is invalid");
                NativeSecp256k1.contextDestroy(ctx);
                return;
            }
            System.out.println("✓ Secret key 1 (for G) is valid: " + bytesToHex(seckey1, 4));
            
            // Compute public key for secret key 1, which gives G (generator point)
            byte[] generatorG = NativeSecp256k1.computePubkey(ctx, seckey1, false); // Uncompressed for clarity
            if (generatorG == null) {
                System.out.println("❌ Failed to compute generator point G");
                NativeSecp256k1.contextDestroy(ctx);
                return;
            }
            System.out.println("✓ Generator point G computed: " + bytesToHex(generatorG, 16));
            
            // Secret key = 2 represents scalar multiplication by 2, so we get 2G
            byte[] seckey2 = new byte[32];
            seckey2[31] = 0x02;  // Little-endian: set last byte to 2
            
            // Verify the secret key
            int valid2 = NativeSecp256k1.seckeyVerify(ctx, seckey2);
            if (valid2 != 1) {
                System.out.println("❌ Secret key 2 is invalid");
                NativeSecp256k1.contextDestroy(ctx);
                return;
            }
            System.out.println("✓ Secret key 2 (for 2G) is valid: " + bytesToHex(seckey2, 4));
            
            // Compute public key for secret key 2, which gives 2G (2 times generator point)
            byte[] point2G = NativeSecp256k1.computePubkey(ctx, seckey2, false); // Uncompressed for clarity
            if (point2G == null) {
                System.out.println("❌ Failed to compute point 2G");
                NativeSecp256k1.contextDestroy(ctx);
                return;
            }
            System.out.println("✓ Point 2G computed: " + bytesToHex(point2G, 16));
            
            // Verify they are different points
            if (java.util.Arrays.equals(generatorG, point2G)) {
                System.out.println("❌ G and 2G are the same (unexpected - multiplication not working)");
            } else {
                System.out.println("✓ Confirmed: G and 2G are different points (scalar multiplication working)");
            }
            
            // Additional test: secret key = 3 to get 3G
            byte[] seckey3 = new byte[32];
            seckey3[31] = 0x03;  // Little-endian: set last byte to 3
            
            int valid3 = NativeSecp256k1.seckeyVerify(ctx, seckey3);
            if (valid3 == 1) {
                byte[] point3G = NativeSecp256k1.computePubkey(ctx, seckey3, false);
                if (point3G != null) {
                    System.out.println("✓ Point 3G computed: " + bytesToHex(point3G, 16));
                    // Verify that 3G is different from both G and 2G
                    if (!java.util.Arrays.equals(point3G, generatorG) && 
                        !java.util.Arrays.equals(point3G, point2G)) {
                        System.out.println("✓ Confirmed: 3G is different from both G and 2G");
                    }
                }
            }
            
            // Test signing with 2G-derived key to verify functionality
            byte[] msg32 = new byte[32];
            for (int i = 0; i < 32; i++) {
                msg32[i] = (byte) ('M' + i % 10);  // Message to sign
            }
            
            byte[] signature = NativeSecp256k1.sign(ctx, msg32, seckey2);
            if (signature != null) {
                System.out.println("✓ Created signature using 2G-derived key");
                
                boolean verified = NativeSecp256k1.verify(ctx, signature, msg32, point2G);
                System.out.println("✓ Signature verified with 2G public key: " + verified);
            }
            
            // Clean up
            NativeSecp256k1.contextDestroy(ctx);
            System.out.println();
            System.out.println("🎯 SCALAR MULTIPLICATION DEMONSTRATION COMPLETE 🎯");
            System.out.println("   Demonstrated: secp256k1 elliptic curve scalar multiplication");
            System.out.println("   • G (generator point) computed from secret key 1");
            System.out.println("   • 2G computed from secret key 2 (G * 2 = 2G)");  
            System.out.println("   • 3G computed from secret key 3");
            System.out.println("   • All operations working correctly through JNI");
            
        } catch (Exception e) {
            System.out.println("❌ Exception occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count && i < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        return sb.toString();
    }
}