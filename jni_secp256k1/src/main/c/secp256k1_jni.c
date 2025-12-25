#include <jni.h>
#include <stdint.h>
#include <string.h>

// Include the secp256k1 library headers
#include "../include/secp256k1.h"
#include "../include/secp256k1_recovery.h"

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    contextCreate
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_org_libsecp256k1_NativeSecp256k1_contextCreate
(JNIEnv *env, jclass clazz, jint flags) {
    secp256k1_context *ctx = secp256k1_context_create((unsigned int)flags);
    return (jlong)(intptr_t)ctx;
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    contextDestroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_libsecp256k1_NativeSecp256k1_contextDestroy
(JNIEnv *env, jclass clazz, jlong ctx_l) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    if (ctx != NULL) {
        secp256k1_context_destroy(ctx);
    }
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    seckeyVerify
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_libsecp256k1_NativeSecp256k1_seckeyVerify
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray seckey) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    jbyte *seckey_bytes = (*env)->GetByteArrayElements(env, seckey, NULL);
    if (seckey_bytes == NULL) {
        return 0; // Exception thrown
    }

    int result = secp256k1_ec_seckey_verify(ctx, (unsigned char *)seckey_bytes);

    (*env)->ReleaseByteArrayElements(env, seckey, seckey_bytes, JNI_ABORT);
    return result;
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    computePubkey
 * Signature: (J[BZ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_libsecp256k1_NativeSecp256k1_computePubkey
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray seckey, jboolean compressed) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    jbyte *seckey_bytes = (*env)->GetByteArrayElements(env, seckey, NULL);
    if (seckey_bytes == NULL) {
        return NULL; // Exception thrown
    }

    secp256k1_pubkey pubkey;
    int result = secp256k1_ec_pubkey_create(ctx, &pubkey, (unsigned char *)seckey_bytes);

    (*env)->ReleaseByteArrayElements(env, seckey, seckey_bytes, JNI_ABORT);

    if (result != 1) {
        return NULL; // Failed
    }

    // Serialize the public key
    jbyteArray resultArray = NULL;
    unsigned char output[65];
    size_t outputlen = 65;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    result = secp256k1_ec_pubkey_serialize(ctx, output, &outputlen, &pubkey, flags);
    if (result == 1) {
        resultArray = (*env)->NewByteArray(env, (jsize)outputlen);
        if (resultArray != NULL) {
            (*env)->SetByteArrayRegion(env, resultArray, 0, (jsize)outputlen, (jbyte *)output);
        }
    }

    return resultArray;
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    sign
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_libsecp256k1_NativeSecp256k1_sign
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray msg32, jbyteArray seckey) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    jbyte *msg32_bytes = (*env)->GetByteArrayElements(env, msg32, NULL);
    jbyte *seckey_bytes = (*env)->GetByteArrayElements(env, seckey, NULL);

    if (msg32_bytes == NULL || seckey_bytes == NULL) {
        if (msg32_bytes) (*env)->ReleaseByteArrayElements(env, msg32, msg32_bytes, JNI_ABORT);
        return NULL; // Exception thrown
    }

    secp256k1_ecdsa_signature signature;
    int result = secp256k1_ecdsa_sign(ctx, &signature, (unsigned char *)msg32_bytes, (unsigned char *)seckey_bytes, NULL, NULL);

    (*env)->ReleaseByteArrayElements(env, msg32, msg32_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, seckey, seckey_bytes, JNI_ABORT);

    if (result != 1) {
        return NULL; // Failed
    }

    // Serialize signature to DER format
    jbyteArray resultArray = NULL;
    unsigned char output[72];
    size_t outputlen = 72;

    result = secp256k1_ecdsa_signature_serialize_der(ctx, output, &outputlen, &signature);
    if (result == 1) {
        resultArray = (*env)->NewByteArray(env, (jsize)outputlen);
        if (resultArray != NULL) {
            (*env)->SetByteArrayRegion(env, resultArray, 0, (jsize)outputlen, (jbyte *)output);
        }
    }

    return resultArray;
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    verify
 * Signature: (J[B[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_libsecp256k1_NativeSecp256k1_verify
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray signature, jbyteArray msg32, jbyteArray pubkey) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    jbyte *sig_bytes = (*env)->GetByteArrayElements(env, signature, NULL);
    jbyte *msg32_bytes = (*env)->GetByteArrayElements(env, msg32, NULL);
    jbyte *pubkey_bytes = (*env)->GetByteArrayElements(env, pubkey, NULL);

    if (sig_bytes == NULL || msg32_bytes == NULL || pubkey_bytes == NULL) {
        if (sig_bytes) (*env)->ReleaseByteArrayElements(env, signature, sig_bytes, JNI_ABORT);
        if (msg32_bytes) (*env)->ReleaseByteArrayElements(env, msg32, msg32_bytes, JNI_ABORT);
        return JNI_FALSE; // Exception thrown
    }

    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pk;
    int sigResult = secp256k1_ecdsa_signature_parse_der(ctx, &sig, (unsigned char *)sig_bytes, (*env)->GetArrayLength(env, signature));
    int pubkeyResult = secp256k1_ec_pubkey_parse(ctx, &pk, (unsigned char *)pubkey_bytes, (*env)->GetArrayLength(env, pubkey));

    (*env)->ReleaseByteArrayElements(env, signature, sig_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, msg32, msg32_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, pubkey, pubkey_bytes, JNI_ABORT);

    if (sigResult != 1 || pubkeyResult != 1) {
        return JNI_FALSE; // Failed to parse
    }

    int result = secp256k1_ecdsa_verify(ctx, &sig, (unsigned char *)msg32_bytes, &pk);

    return result ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    pubkeyParse
 * Signature: (J[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_libsecp256k1_NativeSecp256k1_pubkeyParse
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray input) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    jbyte *input_bytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (input_bytes == NULL) {
        return JNI_FALSE; // Exception thrown
    }

    secp256k1_pubkey pubkey;
    jsize input_len = (*env)->GetArrayLength(env, input);
    int result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char *)input_bytes, (size_t)input_len);

    (*env)->ReleaseByteArrayElements(env, input, input_bytes, JNI_ABORT);

    return result ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    pubkeySerialize
 * Signature: (J[BZ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_libsecp256k1_NativeSecp256k1_pubkeySerialize
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray input, jboolean compressed) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    jbyte *input_bytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (input_bytes == NULL) {
        return NULL; // Exception thrown
    }

    secp256k1_pubkey pubkey;
    jsize input_len = (*env)->GetArrayLength(env, input);
    int parse_result = secp256k1_ec_pubkey_parse(ctx, &pubkey, (unsigned char *)input_bytes, (size_t)input_len);

    (*env)->ReleaseByteArrayElements(env, input, input_bytes, JNI_ABORT);

    if (parse_result != 1) {
        return NULL; // Failed to parse
    }

    unsigned char output[65];
    size_t output_len = 65;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    int result = secp256k1_ec_pubkey_serialize(ctx, output, &output_len, &pubkey, flags);
    if (result != 1) {
        return NULL; // Failed to serialize
    }

    jbyteArray result_array = (*env)->NewByteArray(env, (jsize)output_len);
    if (result_array == NULL) {
        return NULL; // Out of memory
    }

    (*env)->SetByteArrayRegion(env, result_array, 0, (jsize)output_len, (jbyte *)output);
    return result_array;
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    signCompact
 * Signature: (J[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_libsecp256k1_NativeSecp256k1_signCompact
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray msg32, jbyteArray seckey) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    jbyte *msg32_bytes = (*env)->GetByteArrayElements(env, msg32, NULL);
    jbyte *seckey_bytes = (*env)->GetByteArrayElements(env, seckey, NULL);

    if (msg32_bytes == NULL || seckey_bytes == NULL) {
        if (msg32_bytes) (*env)->ReleaseByteArrayElements(env, msg32, msg32_bytes, JNI_ABORT);
        return NULL; // Exception thrown
    }

    secp256k1_ecdsa_signature signature;
    int result = secp256k1_ecdsa_sign(ctx, &signature, (unsigned char *)msg32_bytes, (unsigned char *)seckey_bytes, NULL, NULL);

    (*env)->ReleaseByteArrayElements(env, msg32, msg32_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, seckey, seckey_bytes, JNI_ABORT);

    if (result != 1) {
        return NULL; // Failed
    }

    // Serialize to compact format (64 bytes)
    jbyteArray resultArray = NULL;
    unsigned char output[64];

    result = secp256k1_ecdsa_signature_serialize_compact(ctx, output, &signature);
    if (result == 1) {
        resultArray = (*env)->NewByteArray(env, 64);
        if (resultArray != NULL) {
            (*env)->SetByteArrayRegion(env, resultArray, 0, 64, (jbyte *)output);
        }
    }

    return resultArray;
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    seckeyNegate
 * Signature: (J[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_libsecp256k1_NativeSecp256k1_seckeyNegate
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray seckey) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    jbyte *seckey_bytes = (*env)->GetByteArrayElements(env, seckey, NULL);
    if (seckey_bytes == NULL) {
        return JNI_FALSE; // Exception thrown
    }

    int result = secp256k1_ec_seckey_negate(ctx, (unsigned char *)seckey_bytes);

    if (result == 1) {
        // Update the Java array with the negated secret key
        (*env)->SetByteArrayRegion(env, seckey, 0, 32, seckey_bytes);
    }

    (*env)->ReleaseByteArrayElements(env, seckey, seckey_bytes, JNI_ABORT);

    return result ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    pubkeyNegate
 * Signature: (J[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_libsecp256k1_NativeSecp256k1_pubkeyNegate
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray pubkey) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    jbyte *pubkey_bytes = (*env)->GetByteArrayElements(env, pubkey, NULL);
    if (pubkey_bytes == NULL) {
        return JNI_FALSE; // Exception thrown
    }

    secp256k1_pubkey pk;
    jsize pubkey_len = (*env)->GetArrayLength(env, pubkey);
    int parse_result = secp256k1_ec_pubkey_parse(ctx, &pk, (unsigned char *)pubkey_bytes, (size_t)pubkey_len);

    if (parse_result != 1) {
        (*env)->ReleaseByteArrayElements(env, pubkey, pubkey_bytes, JNI_ABORT);
        return JNI_FALSE; // Failed to parse
    }

    int result = secp256k1_ec_pubkey_negate(ctx, &pk);
    if (result != 1) {
        (*env)->ReleaseByteArrayElements(env, pubkey, pubkey_bytes, JNI_ABORT);
        return JNI_FALSE; // Failed to negate
    }

    // Re-serialize the negated public key back to the Java array
    unsigned char output[65];
    size_t output_len = 65;
    unsigned int flags = (pubkey_len == 33) ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    result = secp256k1_ec_pubkey_serialize(ctx, output, &output_len, &pk, flags);
    if (result != 1) {
        (*env)->ReleaseByteArrayElements(env, pubkey, pubkey_bytes, JNI_ABORT);
        return JNI_FALSE; // Failed to serialize
    }

    if (output_len != (size_t)pubkey_len) {
        (*env)->ReleaseByteArrayElements(env, pubkey, pubkey_bytes, JNI_ABORT);
        return JNI_FALSE; // Size mismatch
    }

    // Update the Java array with the negated public key
    (*env)->SetByteArrayRegion(env, pubkey, 0, (jsize)output_len, (jbyte *)output);

    (*env)->ReleaseByteArrayElements(env, pubkey, pubkey_bytes, 0); // Use 0 to commit changes

    return JNI_TRUE;
}

/*
 * Class:     org_libsecp256k1_NativeSecp256k1
 * Method:    contextRandomize
 * Signature: (J[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_libsecp256k1_NativeSecp256k1_contextRandomize
(JNIEnv *env, jclass clazz, jlong ctx_l, jbyteArray seed32) {
    secp256k1_context *ctx = (secp256k1_context *)(intptr_t)ctx_l;
    unsigned char *seed_ptr = NULL;

    if (seed32 != NULL) {
        jbyte *seed_bytes = (*env)->GetByteArrayElements(env, seed32, NULL);
        if (seed_bytes == NULL) {
            return JNI_FALSE; // Exception thrown
        }
        seed_ptr = (unsigned char *)seed_bytes;
    }

    int result = secp256k1_context_randomize(ctx, seed_ptr);

    if (seed32 != NULL) {
        (*env)->ReleaseByteArrayElements(env, seed32, (jbyte *)seed_ptr, JNI_ABORT);
    }

    return result ? JNI_TRUE : JNI_FALSE;
}