---
title: Crypt32 - RSA Keys 
weight: 2
tags:
    - Cryptography
    - RSA
---

## Source

### Generating RSA keypair
```C {filename=C}
BOOL GenerateRSAKeyPairCryptoAPI(BYTE **publicKey, DWORD *publicKeyLength, BYTE **privateKey, DWORD *privateKeyLength) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL result = FALSE;

    // Acquire cryptographic context
    CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

    // Generate RSA key pair (4096-bit)
    CryptGenKey(hProv, AT_KEYEXCHANGE, (4096 << 16) | CRYPT_EXPORTABLE, &hKey);

    // Export public key blob
    CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, publicKeyLength);

    *publicKey = (BYTE*)malloc(*publicKeyLength);
    CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, *publicKey, publicKeyLength);

    // Export private key blob
    CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, NULL, privateKeyLength);

    *privateKey = (BYTE*)malloc(*privateKeyLength);
    CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, *privateKey, privateKeyLength);

    result = TRUE;

    cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    return result;
}


```

### Bonus, converting to the x509 format
```C {filename=C}
BYTE* ConvertPublicKeyBlobToX509(BYTE *keyBlob, DWORD blobLen, DWORD *x509Length) {
    CERT_PUBLIC_KEY_INFO keyInfo = {0};
    BYTE *x509Data = NULL;

    // Parse the Windows PUBLICKEYBLOB structure
    PUBLICKEYSTRUC *pubKeyStruc = (PUBLICKEYSTRUC*)keyBlob;
    RSAPUBKEY *rsaPubKey = (RSAPUBKEY*)(keyBlob + sizeof(PUBLICKEYSTRUC));


    // Set up algorithm identifier for RSA encryption
    keyInfo.Algorithm.pszObjId = "1.2.840.113549.1.1.1"; // rsaEncryption OID
    keyInfo.Algorithm.Parameters.cbData = 2;

    // ASN.1 NULL parameters (0x05 0x00)
    static BYTE nullParams[] = {0x05, 0x00};
    keyInfo.Algorithm.Parameters.pbData = nullParams;

    // The public key data - we need to convert Windows format to ASN.1
    DWORD keySize = rsaPubKey->bitlen / 8;
    BYTE *modulus = keyBlob + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY);

    // Windows stores RSA modulus in little-endian, need to reverse to big-endian
    BYTE *reversedModulus = (BYTE*)malloc(keySize);
    for (DWORD i = 0; i < keySize; i++) {
        reversedModulus[i] = modulus[keySize - 1 - i];
    }

    // Convert exponent to big-endian bytes
    DWORD exponent = rsaPubKey->pubexp;
    BYTE expBytes[4];
    expBytes[0] = (exponent >> 24) & 0xFF;
    expBytes[1] = (exponent >> 16) & 0xFF;
    expBytes[2] = (exponent >> 8) & 0xFF;
    expBytes[3] = exponent & 0xFF;

    // Find actual exponent length (remove leading zeros)
    int expLen = 4;
    while (expLen > 1 && expBytes[4 - expLen] == 0) {
        expLen--;
    }

    // Build ASN.1 RSAPublicKey structure manually
    // SEQUENCE { modulus INTEGER, exponent INTEGER }
    BYTE rsaPublicKey[4096];
    BYTE *p = rsaPublicKey;

    *p++ = 0x30; // SEQUENCE tag

    // Calculate content length first
    DWORD modIntegerLen = keySize + (reversedModulus[0] & 0x80 ? 1 : 0) + 3; // tag + len + padding + data
    DWORD expIntegerLen = expLen + (expBytes[4-expLen] & 0x80 ? 1 : 0) + 3; // tag + len + padding + data
    DWORD contentLen = modIntegerLen + expIntegerLen;

    if (contentLen > 127) {
        *p++ = 0x82; // long form, 2 bytes
        *p++ = (contentLen >> 8) & 0xFF;
        *p++ = contentLen & 0xFF;
    } else {
        *p++ = (BYTE)contentLen;
    }

    // Modulus INTEGER
    *p++ = 0x02; // INTEGER tag
    DWORD modLen = keySize + (reversedModulus[0] & 0x80 ? 1 : 0);
    if (modLen > 127) {
        *p++ = 0x82;
        *p++ = (modLen >> 8) & 0xFF;
        *p++ = modLen & 0xFF;
    } else {
        *p++ = (BYTE)modLen;
    }
    if (reversedModulus[0] & 0x80) {
        *p++ = 0x00; // padding byte
    }
    memcpy(p, reversedModulus, keySize);
    p += keySize;

    // Exponent INTEGER
    *p++ = 0x02; // INTEGER tag
    DWORD actualExpLen = expLen + (expBytes[4-expLen] & 0x80 ? 1 : 0);
    *p++ = (BYTE)actualExpLen;
    if (expBytes[4-expLen] & 0x80) {
        *p++ = 0x00; // padding byte
    }
    memcpy(p, &expBytes[4-expLen], expLen);
    p += expLen;

    DWORD rsaPublicKeyLen = p - rsaPublicKey;

    // Now use the manually built RSA public key
    keyInfo.PublicKey.cbData = rsaPublicKeyLen;
    keyInfo.PublicKey.pbData = rsaPublicKey;
    keyInfo.PublicKey.cUnusedBits = 0;

    CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &keyInfo, NULL, x509Length);

    x509Data = (BYTE*)malloc(*x509Length);
    CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &keyInfo, x509Data, x509Length);

    free(reversedModulus);
    return x509Data;
}

```