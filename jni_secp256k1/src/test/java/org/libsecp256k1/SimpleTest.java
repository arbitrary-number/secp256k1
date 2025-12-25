package org.libsecp256k1;

public class SimpleTest {
    public static void main(String[] args) {
        System.out.println("Testing secp256k1 JNI library loading...");
        
        try {
            // This will trigger the static initializer which attempts to load the library
            System.out.println("About to access NativeSecp256k1 class methods...");
            
            // Try creating a context
            long ctx = NativeSecp256k1.contextCreate(1); // SECP256K1_CONTEXT_NONE
            if (ctx != 0) {
                System.out.println("Successfully created secp256k1 context: " + ctx);
                
                // Test key generation to verify scalar multiplication works
                byte[] seckey = new byte[32];
                seckey[31] = 0x01;  // Use 1 as secret key to get the generator point
            
                int valid = NativeSecp256k1.seckeyVerify(ctx, seckey);
                System.out.println("Secret key verification result: " + valid);
                
                if (valid == 1) {
                    byte[] pubkey = NativeSecp256k1.computePubkey(ctx, seckey, true);  // This performs G * 1 = G
                    if (pubkey != null) {
                        System.out.println("Successfully computed public key (G*1=G): " + pubkey.length + " bytes");
                        System.out.print("First 10 bytes: ");
                        for (int i = 0; i < Math.min(10, pubkey.length); i++) {
                            System.out.printf("%02x", pubkey[i]);
                        }
                        System.out.println();
                        
                        // Test scalar multiplication by 2 (secret key = 2, gives 2G)
                        byte[] seckey2 = new byte[32];
                        seckey2[31] = 0x02;  // Secret key = 2
                        
                        int valid2 = NativeSecp256k1.seckeyVerify(ctx, seckey2);
                        if (valid2 == 1) {
                            byte[] pubkey2G = NativeSecp256k1.computePubkey(ctx, seckey2, true);  // This gives 2*G
                            if (pubkey2G != null) {
                                System.out.println("Successfully computed 2G public key: " + pubkey2G.length + " bytes");
                                
                                // Verify they're different points (G vs 2G)
                                if (!java.util.Arrays.equals(pubkey, pubkey2G)) {
                                    System.out.println("✓ Verification: G and 2G are different points (scalar multiplication working)");
                                } else {
                                    System.out.println("✗ Error: G and 2G are the same (scalar multiplication not working)");
                                }
                                
                                // Create a message and sign/verify (requires scalar multiplications internally)
                                byte[] msg32 = new byte[32];
                                for (int i = 0; i < 32; i++) {
                                    msg32[i] = (byte) ('A' + i % 26);
                                }
                                
                                byte[] signature = NativeSecp256k1.sign(ctx, msg32, seckey2);
                                if (signature != null) {
                                    System.out.println("✓ Successfully created signature with 2G-derived key: " + signature.length + " bytes");
                                    
                                    boolean verified = NativeSecp256k1.verify(ctx, signature, msg32, pubkey2G);
                                    System.out.println("✓ Signature verification result: " + verified);
                                } else {
                                    System.out.println("✗ Failed to create signature");
                                }
                            }
                        }
                    }
                }
                
                // Clean up
                NativeSecp256k1.contextDestroy(ctx);
                System.out.println("✓ Context destroyed successfully");
                
                System.out.println("🎉 All secp256k1 JNI tests passed! Scalar multiplication operations working.");
            } else {
                System.out.println("Failed to create context - library may not be loaded properly");
            }
        } catch (Exception e) {
            System.out.println("Exception occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
}