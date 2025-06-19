---
title: XOR
weight: 2
tags:
    - Cryptography
    - XOR
---

## Source

### XORing string
```C {filename=C}
void xor_string(char *input) {
    char xorred;
    for (int i = 0; i < strlen(input); i++) {
        xorred = input[i] ^ XOR_KEY;
        input[i] = xorred;
    }
}

```

### XORing numbers
```C {filename=C}
int xor_int(int input) {
    return input ^ XOR_KEY;
}
```