#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulated secp256k1-like structures (mimicking UCRT64 compilation)
typedef struct test_context_struct {
    unsigned char ecmult_gen_ctx[128];  // Placeholder for actual context data
    int flags;
    int initialized;
    unsigned char padding[100];  // Extra space to simulate complex context
} test_context_struct;

typedef struct test_pubkey {
    unsigned char data[64];
} test_pubkey;

typedef struct test_signature {
    unsigned char data[64];
} test_signature;

// Mock implementations that mimic secp256k1 behavior
test_context_struct* mock_context_create(int flags) {
    test_context_struct* ctx = (test_context_struct*)malloc(sizeof(test_context_struct));
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(test_context_struct));
        ctx->flags = flags;
        ctx->initialized = 1;
    }
    return ctx;
}

void mock_context_destroy(test_context_struct* ctx) {
    if (ctx != NULL) {
        // Securely clear sensitive data
        memset(ctx, 0, sizeof(test_context_struct));
        free(ctx);
    }
}

int mock_ec_pubkey_create(const test_context_struct* ctx, test_pubkey* pubkey, const unsigned char* seckey) {
    if (ctx == NULL || pubkey == NULL || seckey == NULL) {
        return 0; // Error
    }
    
    // Initialize the pubkey structure
    memset(pubkey, 0, sizeof(*pubkey));
    
    // Simulate creating a public key from secret key
    for (int i = 0; i < 64; i++) {
        if (i < 32) {
            pubkey->data[i] = seckey[i] ^ 0xAA; // Simple transformation
        } else {
            pubkey->data[i] = 0x55;
        }
    }
    
    return 1; // Success
}

int mock_ecdsa_sign(const test_context_struct* ctx, test_signature* signature, const unsigned char* msg32, const unsigned char* seckey) {
    if (ctx == NULL || signature == NULL || msg32 == NULL || seckey == NULL) {
        return 0;
    }
    
    // Initialize signature structure
    memset(signature, 0, sizeof(*signature));
    
    // Simulate signing
    for (int i = 0; i < 64; i++) {
        if (i < 32) {
            signature->data[i] = msg32[i] ^ seckey[i];
        } else if (i < 64) {
            signature->data[i] = seckey[i-32] ^ 0xFF;
        }
    }
    
    return 1;
}

int mock_ecdsa_verify(const test_context_struct* ctx, const test_signature* signature, const unsigned char* msg32, const test_pubkey* pubkey) {
    if (ctx == NULL || signature == NULL || msg32 == NULL || pubkey == NULL) {
        return 0;
    }
    
    // Simple verification logic
    unsigned char expected_first_byte = msg32[0] ^ pubkey->data[0];
    return (signature->data[0] == expected_first_byte) ? 1 : 0;
}

int mock_ec_seckey_verify(const test_context_struct* ctx, const unsigned char* seckey) {
    if (ctx == NULL || seckey == NULL) {
        return 0;
    }
    
    // Simple validation: reject all zeros
    for (int i = 0; i < 32; i++) {
        if (seckey[i] != 0) {
            return 1; // Valid non-zero key
        }
    }
    return 0; // All zeros is invalid
}

int mock_ec_pubkey_serialize(const test_context_struct* ctx, unsigned char* output, int* outputlen, const test_pubkey* pubkey, int flags) {
    if (ctx == NULL || output == NULL || outputlen == NULL || pubkey == NULL) {
        return 0;
    }
    
    if (*outputlen < 33) {
        return 0; // Buffer too small
    }
    
    int len = (flags & 1) ? 33 : 65; // Compressed or uncompressed
    if (*outputlen < len) {
        return 0;
    }
    
    // Simple serialization
    output[0] = (flags & 1) ? 0x02 : 0x04; // Prefix for compressed/uncompressed
    for (int i = 1; i < len && i < 65; i++) {
        if (i-1 < 64) {
            output[i] = pubkey->data[i-1];
        } else {
            output[i] = 0x00;
        }
    }
    
    *outputlen = len;
    return 1;
}

// JNI Native Method Implementation
JNIEXPORT jlong JNICALL Java_org_test_NativeSecp256k1Wrapper_contextCreate
(JNIEnv *env, jclass clazz, jint flags) {
    test_context_struct* ctx = mock_context_create((int)flags);
    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_test_NativeSecp256k1Wrapper_contextDestroy
(JNIEnv *env, jclass clazz, jlong ctx_l) {
    test_context_struct* ctx = (test_context_struct*)(uintptr_t)ctx_l;
    mock_context_destroy(ctx);
}

JNIEXPORT jbyteArray JNICALL Java_org_test_NativeSecp256k1Wrapper_computePubkey
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray seckey, jboolean compressed) {
    test_context_struct* ctx = (test_context_struct*)(uintptr_t)ctx_l;
    
    // Get the secret key from Java array
    jbyte* seckey_bytes = (*env)->GetByteArrayElements(env, seckey, NULL);
    if (seckey_bytes == NULL) {
        return NULL; // Exception thrown
    }
    
    test_pubkey pubkey;
    int result = mock_ec_pubkey_create(ctx, &pubkey, (unsigned char*)seckey_bytes);
    
    // Release the byte array
    (*env)->ReleaseByteArrayElements(env, seckey, seckey_bytes, JNI_ABORT);
    
    if (result != 1) {
        return NULL; // Failed
    }
    
    // Serialize the public key
    unsigned char output[65];
    int outputlen = 65;
    int flags = compressed ? 1 : 0;
    
    mock_ec_pubkey_serialize(ctx, output, &outputlen, &pubkey, flags);
    
    // Create Java byte array and copy data
    jbyteArray pubkey_array = (*env)->NewByteArray(env, outputlen);
    if (pubkey_array == NULL) {
        return NULL; // Out of memory error thrown
    }
    
    (*env)->SetByteArrayRegion(env, pubkey_array, 0, outputlen, (jbyte*)output);
    return pubkey_array;
}

JNIEXPORT jbyteArray JNICALL Java_org_test_NativeSecp256k1Wrapper_sign
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray msg32, jbyteArray seckey) {
    test_context_struct* ctx = (test_context_struct*)(uintptr_t)ctx_l;
    
    // Get the message and secret key from Java arrays
    jbyte* msg32_bytes = (*env)->GetByteArrayElements(env, msg32, NULL);
    jbyte* seckey_bytes = (*env)->GetByteArrayElements(env, seckey, NULL);
    
    if (msg32_bytes == NULL || seckey_bytes == NULL) {
        // Release any acquired elements
        if (msg32_bytes) (*env)->ReleaseByteArrayElements(env, msg32, msg32_bytes, JNI_ABORT);
        return NULL; // Exception thrown
    }
    
    test_signature signature;
    int result = mock_ecdsa_sign(ctx, &signature, (unsigned char*)msg32_bytes, (unsigned char*)seckey_bytes);
    
    // Release the byte arrays
    (*env)->ReleaseByteArrayElements(env, msg32, msg32_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, seckey, seckey_bytes, JNI_ABORT);
    
    if (result != 1) {
        return NULL; // Failed
    }
    
    // Create Java byte array and copy signature data
    jbyteArray signature_array = (*env)->NewByteArray(env, 64);
    if (signature_array == NULL) {
        return NULL; // Out of memory error thrown
    }
    
    (*env)->SetByteArrayRegion(env, signature_array, 0, 64, (jbyte*)signature.data);
    return signature_array;
}

JNIEXPORT jboolean JNICALL Java_org_test_NativeSecp256k1Wrapper_verify
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray signature, jbyteArray msg32, jbyteArray pubkey) {
    test_context_struct* ctx = (test_context_struct*)(uintptr_t)ctx_l;
    
    // Get the arrays from Java
    jbyte* signature_bytes = (*env)->GetByteArrayElements(env, signature, NULL);
    jbyte* msg32_bytes = (*env)->GetByteArrayElements(env, msg32, NULL);
    jbyte* pubkey_bytes = (*env)->GetByteArrayElements(env, pubkey, NULL);
    
    if (signature_bytes == NULL || msg32_bytes == NULL || pubkey_bytes == NULL) {
        // Release any acquired elements
        if (signature_bytes) (*env)->ReleaseByteArrayElements(env, signature, signature_bytes, JNI_ABORT);
        if (msg32_bytes) (*env)->ReleaseByteArrayElements(env, msg32, msg32_bytes, JNI_ABORT);
        return JNI_FALSE; // Exception thrown
    }
    
    // Create temporary structures
    test_signature sig;
    test_pubkey pk;
    
    // Copy data to structures
    memcpy(sig.data, signature_bytes, 64);
    memcpy(pk.data, pubkey_bytes, 64);
    
    int result = mock_ecdsa_verify(ctx, &sig, (unsigned char*)msg32_bytes, &pk);
    
    // Release the byte arrays
    (*env)->ReleaseByteArrayElements(env, signature, signature_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, msg32, msg32_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, pubkey, pubkey_bytes, JNI_ABORT);
    
    return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_org_test_NativeSecp256k1Wrapper_secKeyVerify
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray seckey) {
    test_context_struct* ctx = (test_context_struct*)(uintptr_t)ctx_l;
    
    // Get the secret key from Java array
    jbyte* seckey_bytes = (*env)->GetByteArrayElements(env, seckey, NULL);
    if (seckey_bytes == NULL) {
        return JNI_FALSE; // Exception thrown
    }
    
    int result = mock_ec_seckey_verify(ctx, (unsigned char*)seckey_bytes);
    
    // Release the byte array
    (*env)->ReleaseByteArrayElements(env, seckey, seckey_bytes, JNI_ABORT);
    
    return result ? JNI_TRUE : JNI_FALSE;
}