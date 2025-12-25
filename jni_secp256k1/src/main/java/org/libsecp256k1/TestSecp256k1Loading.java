package org.libsecp256k1;

/**
 * Simple test to demonstrate the secp256k1 library loading
 */
public class TestSecp256k1Loading {
    
    public static void main(String[] args) {
        System.out.println("Testing secp256k1 library loading...");
        
        try {
            // This will trigger the static initialization in NativeSecp256k1
            System.out.println("Attempting to initialize secp256k1 library...");
            
            // Try to create a context which will verify the library is loaded
            long ctx = NativeSecp256k1.contextCreate(
                NativeSecp256k1.SECP256K1_CONTEXT_SIGN | NativeSecp256k1.SECP256K1_CONTEXT_VERIFY
            );
            
            if (ctx != 0) {
                System.out.println("✓ Successfully created secp256k1 context: " + ctx);
                
                // Test a simple operation
                byte[] seckey = new byte[32];
                seckey[0] = (byte) 0x01;
                
                int valid = NativeSecp256k1.seckeyVerify(ctx, seckey);
                System.out.println("✓ Secret key verification result: " + valid);
                
                NativeSecp256k1.contextDestroy(ctx);
                System.out.println("✓ Context destroyed successfully");
                
                System.out.println("\n✓ All basic secp256k1 operations working!");
            } else {
                System.out.println("✗ Failed to create context - library may not be loaded properly");
            }
        } catch (Exception e) {
            System.out.println("✗ Error during secp256k1 operations: " + e.getMessage());
            e.printStackTrace();
        }
    }
}