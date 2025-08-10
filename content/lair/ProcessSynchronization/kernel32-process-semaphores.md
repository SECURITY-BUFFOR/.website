---
title: Kernel32 - Process Semaphores
weight: 2
tags:
    - Kernel32
    - Synchronization
    - Semaphore
---

## Source
```C {filename=C}
BOOL Semaphore_Create(nt_semaphore_t* ptSem, long lInitial, long lMax) {
    ptSem->hHandle = _CreateSemaphoreW(NULL, lInitial, lMax, NULL);
    return ptSem->hHandle != NULL;
}

BOOL Semaphore_Wait(nt_semaphore_t* ptSem, DWORD dwMs) {
    if (!ptSem || !ptSem->hHandle) return FALSE;
    LARGE_INTEGER liTimeout;
    liTimeout.QuadPart = -(long long)dwMs * 10000LL;
    PLARGE_INTEGER pliTimeout = (dwMs == 0xFFFFFFFF) ? NULL : &liTimeout;
    NTSTATUS status = _NtWaitForSingleObject(ptSem->hHandle, FALSE, pliTimeout);
    return NT_SUCCESS(status);
}

BOOL Semaphore_Signal(nt_semaphore_t* ptSem, long lCount) {
    return _ReleaseSemaphore(ptSem->hHandle, lCount, NULL);
}

void Semaphore_Destroy(nt_semaphore_t* ptSem) {
    if (ptSem->hHandle) _CloseHandle(ptSem->hHandle);
}
```