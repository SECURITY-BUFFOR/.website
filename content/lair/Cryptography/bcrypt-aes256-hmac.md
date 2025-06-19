---
title: Bcrypt - AES256 HMAC
weight: 2
tags:
    - Cryptography
    - AES
---

## Source

### Source of encrypt function
```C {filename=C}
char *aes256_hmac_encrypt(const char *input, const unsigned char *key, const unsigned char *iv, size_t *output_len) {
    // Use simple, well-tested libraries for encryption to match Python behavior
    // 1. Create buffer for output (IV + ciphertext + HMAC)
    size_t input_len = strlen(input);
    size_t padded_len = ((input_len / 16) + 1) * 16; // Round up to multiple of 16
    *output_len = 16 + padded_len + 32; // IV + padded ciphertext + HMAC
    unsigned char *output = (unsigned char *)malloc(*output_len);
    if (!output) return NULL;

    // 2. Copy IV to the beginning of output
    memcpy(output, iv, 16);

    // 3. Encrypt using CBC mode (with proper padding)
    // Initialize AES
    BCRYPT_ALG_HANDLE hAlgAES = NULL;
    BCRYPT_KEY_HANDLE hKeyAES = NULL;
    DWORD cbKeyObject = 0, cbData = 0;
    void *pbKeyObject = NULL;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgAES, BCRYPT_AES_ALGORITHM, NULL, 0);
    if ((long)(status) < 0) {
        free(output);
        return NULL;
    }

    // Set CBC mode
    status = BCryptSetProperty(hAlgAES, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if ((long)(status) < 0) {
        BCryptCloseAlgorithmProvider(hAlgAES, 0);
        free(output);
        return NULL;
    }

    // Get key object size
    status = BCryptGetProperty(hAlgAES, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject,
                                sizeof(DWORD), &cbData, 0);
    if ((long)(status) < 0) {
        BCryptCloseAlgorithmProvider(hAlgAES, 0);
        free(output);
        return NULL;
    }

    // Allocate key object
    pbKeyObject = malloc(cbKeyObject);
    if (!pbKeyObject) {
        BCryptCloseAlgorithmProvider(hAlgAES, 0);
        free(output);
        return NULL;
    }

    // Generate key
    status = BCryptGenerateSymmetricKey(hAlgAES, &hKeyAES, pbKeyObject, cbKeyObject,
                                         (PUCHAR)key, 32, 0);
    if ((long)(status) < 0) {
        free(pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlgAES, 0);
        free(output);
        return NULL;
    }

    // Create a copy of IV for encryption since BCryptEncrypt modifies it
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);

    // Encrypt data
    DWORD cbCipherText = 0;
    status = BCryptEncrypt(hKeyAES, (PUCHAR)input, input_len, NULL, iv_copy, 16,
                            output + 16, padded_len, &cbCipherText, BCRYPT_BLOCK_PADDING);

    // Clean up AES
    BCryptDestroyKey(hKeyAES);
    free(pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlgAES, 0);

    if ((long)(status) < 0) {
        free(output);
        return NULL;
    }

    // 4. Generate HMAC over (IV + ciphertext)
    BCRYPT_ALG_HANDLE hAlgHMAC = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0;
    void *pbHashObject = NULL;

    status = BCryptOpenAlgorithmProvider(&hAlgHMAC, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if ((long)(status) < 0) {
        free(output);
        return NULL;
    }

    // Get hash object size
    status = BCryptGetProperty(hAlgHMAC, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject,
                                sizeof(DWORD), &cbData, 0);
    if ((long)(status) < 0) {
        BCryptCloseAlgorithmProvider(hAlgHMAC, 0);
        free(output);
        return NULL;
    }

    // Allocate hash object if needed
    if (cbHashObject > 0) {
        pbHashObject = malloc(cbHashObject);
        if (!pbHashObject) {
            BCryptCloseAlgorithmProvider(hAlgHMAC, 0);
            free(output);
            return NULL;
        }
    }

    // Create hash
    status = BCryptCreateHash(hAlgHMAC, &hHash, pbHashObject, cbHashObject,
                               (PUCHAR)key, 32, 0);
    if ((long)(status) < 0) {
        if (pbHashObject) free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlgHMAC, 0);
        free(output);
        return NULL;
    }

    // Hash IV
    status = BCryptHashData(hHash, output, 16, 0);
    if ((long)(status) < 0) {
        BCryptDestroyHash(hHash);
        if (pbHashObject) free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlgHMAC, 0);
        free(output);
        return NULL;
    }

    // Hash ciphertext
    status = BCryptHashData(hHash, output + 16, cbCipherText, 0);
    if ((long)(status) < 0) {
        BCryptDestroyHash(hHash);
        if (pbHashObject) free(pbHashObject);
        BCryptCloseAlgorithmProvider(hAlgHMAC, 0);
        free(output);
        return NULL;
    }

    // Finalize HMAC
    status = BCryptFinishHash(hHash, output + 16 + cbCipherText, 32, 0);

    // Clean up HMAC
    BCryptDestroyHash(hHash);
    if (pbHashObject) free(pbHashObject);
    BCryptCloseAlgorithmProvider(hAlgHMAC, 0);

    if ((long)(status) < 0) {
        free(output);
        return NULL;
    }

    // Update output length based on actual ciphertext size
    *output_len = 16 + cbCipherText + 32;

    return (char *)output;
}
```

### Source of decrypt function
```C {filename=C}

char *aes256_hmac_decrypt(const char *input, size_t input_len, const unsigned char *key, size_t *output_len) {
    if (input_len < 16 + 32) return NULL; // Input must at least have IV (16) + HMAC (32)

    BCRYPT_ALG_HANDLE hAlgAES = NULL, hAlgHMAC = NULL;
    BCRYPT_KEY_HANDLE hKeyAES = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbKeyObject = 0, cbData = 0, cbPlainText = 0, cbHashObject = 0;
    void *pbKeyObject = NULL, *pbPlainText = NULL, *computed_hmac = NULL, *pbHashObject = NULL;
    char *output = NULL;
    NTSTATUS status;

    // Use same key for both AES and HMAC (first 32 bytes only)
    const unsigned char *aes_key = key;
    const unsigned char *hmac_key = key;  // Changed: use same key

    // Extract components from input
    const unsigned char *iv = (const unsigned char *) input;
    size_t ciphertext_len = input_len - 16 - 32;
    const unsigned char *ciphertext = (const unsigned char *) input + 16;
    const unsigned char *provided_hmac = (const unsigned char *) input + 16 + ciphertext_len;

    // Open AES provider
    status = BCryptOpenAlgorithmProvider(&hAlgAES, BCRYPT_AES_ALGORITHM, NULL, 0);
    if ((long) (status) < 0) return NULL;

    // Set AES to CBC mode (same as encrypt function)
    status = BCryptSetProperty(hAlgAES, BCRYPT_CHAINING_MODE, (PUCHAR) BCRYPT_CHAIN_MODE_CBC,
                                sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if ((long) (status) < 0) goto cleanup;

    // Open HMAC-SHA256 provider
    status = BCryptOpenAlgorithmProvider(&hAlgHMAC, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if ((long) (status) < 0) goto cleanup;

    // Get HMAC hash object size
    status = BCryptGetProperty(hAlgHMAC, BCRYPT_OBJECT_LENGTH, (PUCHAR) &cbHashObject,
                                sizeof(DWORD), &cbData, 0);
    if ((long) (status) < 0) goto cleanup;

    // Allocate hash object if needed
    if (cbHashObject > 0) {
        pbHashObject = malloc(cbHashObject);
        if (!pbHashObject) goto cleanup;
    }

    // Create HMAC hash
    status = BCryptCreateHash(hAlgHMAC, &hHash, pbHashObject, cbHashObject,
                               (PUCHAR) hmac_key, 32, 0);
    if ((long) (status) < 0) goto cleanup;

    // Hash the IV
    status = BCryptHashData(hHash, (PUCHAR) iv, 16, 0);
    if ((long) (status) < 0) goto cleanup;

    // Hash the ciphertext
    status = BCryptHashData(hHash, (PUCHAR) ciphertext, ciphertext_len, 0);
    if ((long) (status) < 0) goto cleanup;

    // Allocate HMAC output buffer
    computed_hmac = malloc(32);
    if (!computed_hmac) goto cleanup;

    // Finalize HMAC
    status = BCryptFinishHash(hHash, computed_hmac, 32, 0);
    if ((long) (status) < 0) goto cleanup;

    // Verify HMAC
    if (memcmp(computed_hmac, provided_hmac, 32) != 0) {
        // HMAC verification failed - data may have been tampered with
        goto cleanup;
    }

    // Get AES key object size
    status = BCryptGetProperty(hAlgAES, BCRYPT_OBJECT_LENGTH, (PUCHAR) &cbKeyObject,
                                sizeof(DWORD), &cbData, 0);
    if ((long) (status) < 0) goto cleanup;

    // Allocate key object
    pbKeyObject = malloc(cbKeyObject);
    if (!pbKeyObject) goto cleanup;

    // Generate AES key
    status = BCryptGenerateSymmetricKey(hAlgAES, &hKeyAES, pbKeyObject, cbKeyObject,
                                         (PUCHAR) aes_key, 32, 0);
    if ((long) (status) < 0) goto cleanup;

    // Create a copy of IV for decryption since BCryptDecrypt modifies it
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16);

    // Get plaintext size
    status = BCryptDecrypt(hKeyAES, (PUCHAR) ciphertext, ciphertext_len, NULL, iv_copy, 16,
                            NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if ((long) (status) < 0) goto cleanup;

    // Allocate plaintext buffer with space for null terminator
    pbPlainText = malloc(cbPlainText + 1);
    if (!pbPlainText) goto cleanup;

    // Reset IV copy for actual decryption
    memcpy(iv_copy, iv, 16);

    // Decrypt the data with CBC mode and padding
    status = BCryptDecrypt(hKeyAES, (PUCHAR) ciphertext, ciphertext_len, NULL, iv_copy, 16,
                            pbPlainText, cbPlainText, &cbData, BCRYPT_BLOCK_PADDING);
    if ((long) (status) < 0) goto cleanup;

    // Add null terminator
    ((unsigned char *) pbPlainText)[cbData] = 0;

    *output_len = cbData;
    output = (char *) pbPlainText;
    pbPlainText = NULL; // Prevent freeing in cleanup

    cleanup:
    if (hKeyAES) BCryptDestroyKey(hKeyAES);
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlgAES) BCryptCloseAlgorithmProvider(hAlgAES, 0);
    if (hAlgHMAC) BCryptCloseAlgorithmProvider(hAlgHMAC, 0);
    if (pbKeyObject) free(pbKeyObject);
    if (pbHashObject) free(pbHashObject);
    if (pbPlainText) free(pbPlainText);
    if (computed_hmac) free(computed_hmac);

    return output;
}
```