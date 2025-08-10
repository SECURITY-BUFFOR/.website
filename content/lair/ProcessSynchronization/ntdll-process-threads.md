---
title: NTDLL - Process Threads
weight: 2
tags:
    - NTDLL
    - Synchronization
    - Thread
---

## Source
```C {filename=C}
void Thread_Create(nt_thread_t* ptThread, pfnThreadProc pfnProc, void* pvArg) {
    if (!ptThread || !pfnProc) return;

    // This can be _RtlCreateUserThread or _NtCreateThreadEx
    NTSTATUS status = _RtlCreateUserThread(
            _GetCurrentProcess(), NULL, FALSE, 0, 0, 0,
            (PVOID)pfnProc, pvArg, &ptThread->hHandle, &ptThread->cid
    );

}

BOOL Thread_Join(nt_thread_t* ptThread) {
    if (!ptThread || ptThread->hHandle == NULL) return FALSE;
    NTSTATUS status = _NtWaitForSingleObject(ptThread->hHandle, FALSE, NULL);
    return NT_SUCCESS(status);
}

void Thread_Close(nt_thread_t* ptThread) {
    if (ptThread && ptThread->hHandle) {
        _CloseHandle(ptThread->hHandle);
        ptThread->hHandle = NULL;
    }
}

```