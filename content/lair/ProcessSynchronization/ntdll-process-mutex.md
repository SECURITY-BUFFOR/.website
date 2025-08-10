---
title: NTDLL - Process Mutex
weight: 2
tags:
    - NTDLL
    - Synchronization
    - Mutex
---

## Source
```C {filename=C}
void Mutex_Init(nt_mutex_t* ptMtx) {
    _RtlInitializeCriticalSection(&ptMtx->tCs);
}

void Mutex_Lock(nt_mutex_t* ptMtx) {
    _RtlEnterCriticalSection(&ptMtx->tCs);
}

void Mutex_Unlock(nt_mutex_t* ptMtx) {
    _RtlLeaveCriticalSection(&ptMtx->tCs);
}

void Mutex_Destroy(nt_mutex_t* ptMtx) {
    _RtlDeleteCriticalSection(&ptMtx->tCs);
}
```