---
title: WinHTTP - HTTP Communication
weight: 2
tags:
    - WinHTTP
    - Communication
    - HTTP
    - HTTPS
---
## Structure of the HTTP Response
```C {filename=C}
typedef struct {
    DWORD statusCode;
    char *responseText;
} HTTPResponse;
```
## Source
```C {filename=C}
HTTPResponse SendHttpRequest(const char *url, const char *urlpath, const char *post_data, const char *headers, BOOL ssl,
                             BOOL is_post) {
    HTTPResponse response;
    response.statusCode = 0;
    response.responseText = NULL;

    HINTERNET hSession = WinHttpOpen(L"Client App/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        response.statusCode = 1;
        return response;
    }

    URL_COMPONENTS urlComp;
    memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    WCHAR hostname[256];
    WCHAR path[1024];
    urlComp.lpszHostName = hostname;
    urlComp.dwHostNameLength = sizeof(hostname) / sizeof(WCHAR);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = sizeof(path) / sizeof(WCHAR);

    int urlLength = _MultiByteToWideChar(0, 0, url, -1, NULL, 0);
    WCHAR *wideUrl = (WCHAR *) malloc(urlLength * sizeof(WCHAR));
    _MultiByteToWideChar(0, 0, url, -1, wideUrl, urlLength);

    if (!WinHttpCrackUrl(wideUrl, (DWORD) wcslen(wideUrl), 0, &urlComp)) {
        free(wideUrl);
        WinHttpCloseHandle(hSession);
        response.statusCode = 2;
        return response;
    }
    free(wideUrl);

    HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        response.statusCode = 3;
        return response;
    }

    int urlpathLength = _MultiByteToWideChar(0, 0, urlpath, -1, NULL, 0);
    WCHAR *wideUrlPath = (WCHAR *) malloc(urlpathLength * sizeof(WCHAR));
    _MultiByteToWideChar(0, 0, urlpath, -1, wideUrlPath, urlpathLength);

    LPCWSTR pwszVerb = is_post ? L"POST" : L"GET";
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, pwszVerb, wideUrlPath, NULL, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, ssl ? WINHTTP_FLAG_SECURE : 0);
    free(wideUrlPath);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        response.statusCode = 4;
        return response;
    }

    int headersLength = _MultiByteToWideChar(0, 0, headers, -1, NULL, 0);
    WCHAR *wideHeaders = (WCHAR *) malloc(headersLength * sizeof(WCHAR));
    _MultiByteToWideChar(0, 0, headers, -1, wideHeaders, headersLength);


    BOOL bResults;
    if (is_post) {
        bResults = WinHttpSendRequest(hRequest, wideHeaders, 0, (LPVOID) post_data, (DWORD) strlen(post_data),
                                       (DWORD) strlen(post_data), 0);
    } else {
        bResults = WinHttpSendRequest(hRequest, wideHeaders, 0, NULL, 0, 0, 0);
    }

    if (!bResults) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        response.statusCode = 5;
        return response;
    }

    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        response.statusCode = 6;
        return response;
    }

    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    DWORD totalSize = 0;
    LPSTR responseText = (LPSTR) malloc(1);
    *responseText = '\0';

    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;

        pszOutBuffer = (LPSTR) malloc(dwSize + 1);
        if (!pszOutBuffer) break;

        RtlZeroMemory(pszOutBuffer, dwSize + 1);

        if (!WinHttpReadData(hRequest, (LPVOID) pszOutBuffer, dwSize, &dwDownloaded)) {
            free(pszOutBuffer);
            break;
        }

        // Increase totalSize for realloc
        LPSTR newBuffer = (LPSTR) realloc(responseText, totalSize + dwDownloaded + 1);
        if (!newBuffer) {
            free(pszOutBuffer);
            break;
        }

        responseText = newBuffer;
        memcpy(responseText + totalSize, pszOutBuffer, dwDownloaded);
        totalSize += dwDownloaded;
        responseText[totalSize] = '\0';  // null-terminate

        free(pszOutBuffer);

    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    response.statusCode = 200;
    response.responseText = responseText;
    return response;
}

HTTPResponse SendGet(const char *url, const char *urlpath, const char *headers, BOOL ssl) {
    return SendHttpRequest(url, urlpath, NULL, headers, ssl, FALSE);
}

HTTPResponse SendPost(const char *url, const char *urlpath, const char *headers, const char *body, BOOL ssl) {
    return SendHttpRequest(url, urlpath, body, headers, ssl, TRUE);
}
```