---
title: Kernel32 - Process Events
weight: 2
tags:
    - Kernel32
    - Synchronization
    - Event
    - Signaling
---

## Source
```C {filename=C}
BOOL Event_Create(nt_event_t* ptEvt, BOOL bManualReset, BOOL bInitialState) {
    ptEvt->hHandle = _CreateEventW(NULL, bManualReset, bInitialState, NULL);
    return ptEvt->hHandle != NULL;
}

BOOL Event_Wait(nt_event_t* ptEvt, DWORD dwMs) {
    if (!ptEvt || !ptEvt->hHandle) return FALSE;
    LARGE_INTEGER liTimeout;
    liTimeout.QuadPart = -(long long)dwMs * 10000LL;
    PLARGE_INTEGER pliTimeout = (dwMs == 0xFFFFFFFF) ? NULL : &liTimeout;
    NTSTATUS status = _NtWaitForSingleObject(ptEvt->hHandle, FALSE, pliTimeout);
    return NT_SUCCESS(status);
}

BOOL Event_Signal(nt_event_t* ptEvt) {
    return _SetEvent(ptEvt->hHandle);
}

BOOL Event_Reset(nt_event_t* ptEvt) {
    return _ResetEvent(ptEvt->hHandle);
}

void Event_Destroy(nt_event_t* ptEvt) {
    if (ptEvt->hHandle) _CloseHandle(ptEvt->hHandle);
}
```