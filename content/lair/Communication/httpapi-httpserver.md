---
title: HTTPApi - HTTP Server
weight: 2
tags:
    - httpapi
    - server
    - HTTP
    - HTTPS
---
## Example Source
```C {filename=C}
void run_http_server() {
    ULONG result;
    HTTPAPI_VERSION httpVersion = HTTPAPI_VERSION_1; // USE VERSION 2 if you want it's {2, 0}
    HANDLE requestQueue = NULL;
    HTTP_REQUEST* request;
    HTTP_RESPONSE response;
    ULONG bytesReceived;
    BOOL running = TRUE;

    // Initialize HTTP Server API
    result = HttpInitialize(httpVersion, HTTP_INITIALIZE_SERVER, NULL);
    if (result != NO_ERROR) {
        printf("HttpInitialize failed: %lu\n", result);
        return;
    }

    // Create HTTP Request Queue
    result = HttpCreateHttpHandle(&requestQueue, 0);
    if (result != NO_ERROR) {
        printf("HttpCreateHttpHandle failed: %lu\n", result);
        HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
        return;
    }

    // Add URL to the request queue
    result = HttpAddUrl(requestQueue, L"http://localhost:8080/", NULL);
    if (result != NO_ERROR) {
        printf("HttpAddUrl failed: %lu\n", result);
        CloseHandle(requestQueue);
        HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
        return;
    }

    printf("Listening on http://localhost:8080/\n");

    // Allocate memory for HTTP request
    request = (HTTP_REQUEST*)malloc(BUFFER_SIZE);
    if (!request) {
        printf("Memory allocation failed\n");
        HttpRemoveUrl(requestQueue, L"http://localhost:8080/");
        CloseHandle(requestQueue);
        HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
        return;
    }

    // Listen for incoming requests
    while (running) {
        RtlZeroMemory(request, BUFFER_SIZE);

        // Receive an HTTP request
        result = HttpReceiveHttpRequest(requestQueue, 0, 0, request, BUFFER_SIZE, &bytesReceived, NULL);
        if (result == NO_ERROR) {
            printf("Received request for: %ws\n", request->CookedUrl.pFullUrl);

            // Prepare HTTP response
            RtlZeroMemory(&response, sizeof(HTTP_RESPONSE));
            response.StatusCode = 200;
            response.pReason = "OK";
            response.ReasonLength = (USHORT)strlen("OK");

            HTTP_DATA_CHUNK dataChunk;
            const char* responseBody = "Hello, World!";
            dataChunk.DataChunkType = HttpDataChunkFromMemory;
            dataChunk.FromMemory.pBuffer = (PVOID)responseBody;
            dataChunk.FromMemory.BufferLength = (ULONG)strlen(responseBody);

            response.EntityChunkCount = 1;
            response.pEntityChunks = &dataChunk;

            // Send HTTP response
            result = HttpSendHttpResponse(requestQueue, request->RequestId, 0, &response, NULL, NULL, NULL, 0, NULL, NULL);
            if (result != NO_ERROR) {
                printf("HttpSendHttpResponse failed: %lu\n", result);
            }
        } else {
            printf("HttpReceiveHttpRequest failed: %lu\n", result);
            if (result == ERROR_OPERATION_ABORTED) {
                printf("Server shutting down...\n");
                running = FALSE;
            }
        }
    }

    // Clean up resources
    free(request);
    HttpRemoveUrl(requestQueue, L"http://localhost:8080/");
    CloseHandle(requestQueue);
    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);

}
```