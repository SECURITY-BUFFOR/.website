---
title: Bcrypt - AES256 CBC
weight: 2
tags:
    - Cryptography
    - AES
---

## Source

### Source of encrypt function
```C {filename=C}
char *aes256_encrypt(const char *input, const unsigned char *key, size_t *output_len) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbData = 0, cbCipherText = 0;
    PBYTE pbKeyObject = NULL;
    PBYTE pbCipherText = NULL;
    PBYTE pbIV = NULL;
    NTSTATUS status;
    char *output = NULL;

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to open algorithm provider: 0x%x\n", status);
        return NULL;
    }

    // Set the chaining mode to CBC
    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to set chaining mode: 0x%x\n", status);
        goto cleanup;
    }

    // Calculate the size of the key object
    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(cbKeyObject), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to get object length: 0x%x\n", status);
        goto cleanup;
    }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        fprintf(stderr, "Memory allocation failed for key object\n");
        goto cleanup;
    }

    // Generate the key
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, pbKeyObject, cbKeyObject, (PUCHAR)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to generate symmetric key: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate IV (initialization vector)
    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AES_BLOCK_SIZE);
    if (!pbIV) {
        fprintf(stderr, "Memory allocation failed for IV\n");
        goto cleanup;
    }
    ZeroMemory(pbIV, AES_BLOCK_SIZE);

    // Calculate the required buffer size for ciphertext
    status = BCryptEncrypt(hKey, (PUCHAR)input, (ULONG)strlen(input), NULL, pbIV, AES_BLOCK_SIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to calculate ciphertext size: 0x%x\n", status);
        goto cleanup;
    }

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (!pbCipherText) {
        fprintf(stderr, "Memory allocation failed for ciphertext\n");
        goto cleanup;
    }

    // Perform the encryption
    status = BCryptEncrypt(hKey, (PUCHAR)input, (ULONG)strlen(input), NULL, pbIV, AES_BLOCK_SIZE, pbCipherText, cbCipherText, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Encryption failed: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate output buffer and copy ciphertext
    output = (char *)HeapAlloc(GetProcessHeap(), 0, cbData);
    if (!output) {
        fprintf(stderr, "Memory allocation failed for output\n");
        goto cleanup;
    }
    memcpy(output, pbCipherText, cbData);
    *output_len = cbData;

    cleanup:
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (hKey) BCryptDestroyKey(hKey);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbCipherText) HeapFree(GetProcessHeap(), 0, pbCipherText);
    if (pbIV) HeapFree(GetProcessHeap(), 0, pbIV);

    return output;
}
```

### Source of decrypt function
```C {filename=C}

char *aes256_decrypt(const char *input, size_t input_len, const unsigned char *key, size_t *output_len) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObject = 0, cbData = 0, cbPlainText = 0;
    PBYTE pbKeyObject = NULL;
    PBYTE pbPlainText = NULL;
    PBYTE pbIV = NULL;
    NTSTATUS status;
    char *output = NULL;

    // Open an algorithm handle
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to open algorithm provider: 0x%x\n", status);
        return NULL;
    }

    // Set the chaining mode to CBC
    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to set chaining mode: 0x%x\n", status);
        goto cleanup;
    }

    // Calculate the size of the key object
    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(cbKeyObject), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to get object length: 0x%x\n", status);
        goto cleanup;
    }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        fprintf(stderr, "Memory allocation failed for key object\n");
        goto cleanup;
    }

    // Generate the key
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, pbKeyObject, cbKeyObject, (PUCHAR)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to generate symmetric key: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate IV (initialization vector)
    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AES_BLOCK_SIZE);
    if (!pbIV) {
        fprintf(stderr, "Memory allocation failed for IV\n");
        goto cleanup;
    }
    ZeroMemory(pbIV, AES_BLOCK_SIZE);

    // Calculate the required buffer size for plaintext
    status = BCryptDecrypt(hKey, (PUCHAR)input, (ULONG)input_len, NULL, pbIV, AES_BLOCK_SIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Failed to calculate plaintext size: 0x%x\n", status);
        goto cleanup;
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (!pbPlainText) {
        fprintf(stderr, "Memory allocation failed for plaintext\n");
        goto cleanup;
    }

    // Perform the decryption
    status = BCryptDecrypt(hKey, (PUCHAR)input, (ULONG)input_len, NULL, pbIV, AES_BLOCK_SIZE, pbPlainText, cbPlainText, &cbData, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Decryption failed: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate output buffer and copy plaintext
    output = (char *)HeapAlloc(GetProcessHeap(), 0, cbData + 1); // Add 1 for null terminator
    if (!output) {
        fprintf(stderr, "Memory allocation failed for output\n");
        goto cleanup;
    }
    memcpy(output, pbPlainText, cbData);
    output[cbData] = '\0'; // Null-terminate the string
    *output_len = cbData;

    cleanup:
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (hKey) BCryptDestroyKey(hKey);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText) HeapFree(GetProcessHeap(), 0, pbPlainText);
    if (pbIV) HeapFree(GetProcessHeap(), 0, pbIV);

    return output;
}
```