---
title: Crypt32 - Base64
weight: 2
tags:
    - Cryptography
    - Base64
---

## Source

### Source of encrypt function
```C {filename=C}
BOOL Base64Encode(const char* text, char** base64) {
    if (text == NULL || strlen(text) == 0)
        return FALSE;

    // Get the length of the binary data.
    DWORD dwBinaryLen = strlen(text);
    const BYTE* pbBinary = (const BYTE*)text;

    // Calculate the length of the base64 encoded string.
    DWORD dwSize = 0;
    if (!CryptBinaryToStringA(pbBinary, dwBinaryLen, 0x00000001 | 0x40000000, NULL, &dwSize)) {
        return FALSE;
    }

    // Allocate memory for the base64 string.
    *base64 = (char*)malloc(dwSize);
    if (*base64 == NULL) {
        return FALSE;
    }

    // Perform the encoding.
    if (!CryptBinaryToStringA(pbBinary, dwBinaryLen, 0x00000001 | 0x40000000, *base64, &dwSize)) {
        free(*base64);
        return FALSE;
    }

    return TRUE;
}
```

### Source of decrypt function
```C {filename=C}

BOOL Base64Decode(const char* base64Input, char** outputText) {
    if (base64Input == NULL || strlen(base64Input) == 0) {
        return FALSE;
    }

    DWORD dwSize = 0;
    // First, get the required size for the output buffer
    if (!CryptStringToBinaryA(base64Input, strlen(base64Input), 0x00000001, NULL, &dwSize, NULL, NULL)) {
        return FALSE;
    }

    // Allocate buffer for decoded string
    BYTE* decodedBytes = (BYTE*)malloc(dwSize);
    if (decodedBytes == NULL) {
        return FALSE;
    }

    // Perform the actual decoding
    if (!CryptStringToBinaryA(base64Input, strlen(base64Input), 0x00000001, decodedBytes, &dwSize, NULL, NULL)) {
        free(decodedBytes);
        return FALSE;
    }

    // Allocate memory for the output string and copy the result.
    *outputText = (char*)malloc(dwSize + 1);
    if (*outputText == NULL) {
        free(decodedBytes);
        return FALSE;
    }
    memcpy(*outputText, decodedBytes, dwSize);
    // Null-terminate the string
    (*outputText)[dwSize] = '\0'; 

    free(decodedBytes);
    return TRUE;
}
```