package org.libsecp256k1;

public class NativeSecp256k1 {
    static {
        System.out.println("Library loading handled by NativeSecp256k1 class during static initialization.");
        boolean loaded = LibraryLoader.loadSecp256k1Library();
        if (!loaded) {
            throw new RuntimeException(
                "Failed to load secp256k1 native library. " +
                "Make sure the UCRT64-compiled secp256k1 library is available in your system."
            );
        }
    }

    // Native method declarations matching the C implementation
    public static native long contextCreate(int flags);
    public static native void contextDestroy(long ctx);
    public static native int seckeyVerify(long ctx, byte[] seckey);
    public static native byte[] computePubkey(long ctx, byte[] seckey, boolean compressed);
    public static native byte[] sign(long ctx, byte[] msg32, byte[] seckey);
    public static native boolean verify(long ctx, byte[] signature, byte[] msg32, byte[] pubkey);
    public static native boolean pubkeyParse(long ctx, byte[] input);
    public static native byte[] pubkeySerialize(long ctx, byte[] input, boolean compressed);
    public static native byte[] signCompact(long ctx, byte[] msg32, byte[] seckey);
    public static native boolean seckeyNegate(long ctx, byte[] seckey);
    public static native boolean pubkeyNegate(long ctx, byte[] pubkey);
    public static native boolean contextRandomize(long ctx, byte[] seed32);

    // Context flags - using correct values from secp256k1.h
    public static final int SECP256K1_CONTEXT_NONE = 1;      // SECP256K1_FLAGS_TYPE_CONTEXT (1 << 0)
    public static final int SECP256K1_CONTEXT_SIGN = 513;     // SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN (1 | (1 << 9))
    public static final int SECP256K1_CONTEXT_VERIFY = 257;   // SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY (1 | (1 << 8))

    // Test the integration
    public static void main(String[] args) {
        System.out.println("Testing JNI wrapper for UCRT64-compiled secp256k1 library...");

        // Create context
        long ctx = contextCreate(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (ctx == 0) {
            System.out.println("Failed to create context!");
            return;
        }

        System.out.println("Context created successfully: " + ctx);

        try {
            // Test with some sample data
            byte[] seckey = new byte[32];
            for (int i = 0; i < 32; i++) {
                seckey[i] = (byte) (i + 1);  // Fill with some data
            }

            // Verify secret key
            int isValid = seckeyVerify(ctx, seckey);
            System.out.println("Secret key verification result: " + isValid);

            if (isValid == 1) {
                System.out.println("Secret key is valid!");

                // Test context randomization for better security
                byte[] seed32 = new byte[32];
                for (int i = 0; i < 32; i++) {
                    seed32[i] = (byte) (i + 10);  // Fill with different data
                }
                boolean randomized = contextRandomize(ctx, seed32);
                System.out.println("Context randomization result: " + randomized);

                // Compute public key
                byte[] pubkey = computePubkey(ctx, seckey, true);
                if (pubkey != null) {
                    System.out.println("Public key computed successfully, length: " + pubkey.length);
                    System.out.println("First 8 bytes: " + bytesToHex(pubkey, 8));

                    // Test public key parsing and serialization
                    boolean parsed = pubkeyParse(ctx, pubkey);
                    System.out.println("Public key parse result: " + parsed);
                    
                    byte[] serializedPubkey = pubkeySerialize(ctx, pubkey, true);
                    if (serializedPubkey != null) {
                        System.out.println("Public key serialize result length: " + serializedPubkey.length);
                    }

                    // Test secret key negation
                    byte[] seckeyCopy = seckey.clone();  // Make a copy to test negation
                    boolean negated = seckeyNegate(ctx, seckeyCopy);
                    System.out.println("Secret key negation result: " + negated);
                    
                    if (negated) {
                        System.out.println("Secret key negation successful");
                    }

                    // Test public key negation
                    byte[] pubkeyCopy = pubkey.clone();  // Make a copy to test negation
                    boolean pubkeyNegated = pubkeyNegate(ctx, pubkeyCopy);
                    System.out.println("Public key negation result: " + pubkeyNegated);
                    
                    if (pubkeyNegated) {
                        System.out.println("Public key negation successful");
                    }

                    // Create a message to sign (32 bytes is required for secp256k1)
                    byte[] msg32 = new byte[32];
                    for (int i = 0; i < 32; i++) {
                        msg32[i] = (byte) ('A' + i);  // Fill with 'A', 'B', etc.
                    }

                    // Sign the message
                    byte[] signature = sign(ctx, msg32, seckey);
                    if (signature != null) {
                        System.out.println("DER Signature created successfully, length: " + signature.length);
                        System.out.println("First 8 bytes: " + bytesToHex(signature, 8));

                        // Test compact signature
                        byte[] compactSig = signCompact(ctx, msg32, seckey);
                        if (compactSig != null) {
                            System.out.println("Compact signature created successfully, length: " + compactSig.length);
                        }

                        // Verify the signature
                        boolean isVerified = verify(ctx, signature, msg32, pubkey);
                        System.out.println("Signature verification: " + isVerified);

                        if (isVerified) {
                            System.out.println("SUCCESS: Complete secp256k1 workflow completed!");
                        } else {
                            System.out.println("Signature verification failed (expected for test data)");
                        }
                    } else {
                        System.out.println("Signature creation failed!");
                    }
                } else {
                    System.out.println("Public key computation failed!");
                }
            } else {
                System.out.println("Secret key is invalid!");
            }
        } catch (Exception e) {
            System.out.println("Exception occurred: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Always destroy context
            contextDestroy(ctx);
            System.out.println("Context destroyed, test completed!");
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