#include "header.h"

void GetDateOneMonthAgo(wchar_t* buffer, size_t bufferSize)
{
    SYSTEMTIME st;
    FILETIME ft;
    ULONGLONG qwTime;

    GetSystemTime(&st);  
    SystemTimeToFileTime(&st, &ft);

    qwTime = (((ULONGLONG)ft.dwHighDateTime) << 32) + ft.dwLowDateTime;

    

    qwTime -= 30ULL * 24ULL * 3600ULL * 10000000ULL;

    ft.dwLowDateTime = (DWORD)(qwTime & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(qwTime >> 32);

    FileTimeToSystemTime(&ft, &st);

 
    swprintf(buffer, bufferSize, L"%04d-%02d-%02dT%02d:%02d:%02dZ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

void ExtractValue(const wchar_t* xml, const wchar_t* tag, wchar_t* out, size_t outSize)
{
    const wchar_t* start = wcsstr(xml, tag);
    if (!start) return;

    start = wcschr(start, L'>');
    if (!start) return;

    start++; // Vai dopo il '>'
    const wchar_t* end = wcschr(start, L'<');
    if (!end) return;

    size_t len = end - start;
    if (len >= outSize) len = outSize - 1;

    wcsncpy_s(out, outSize, start, len);
}

void ExtractAttributeValue(const wchar_t* xml, const wchar_t* tag, const wchar_t* attr, wchar_t* out, size_t outSize)
{
    const wchar_t* start = wcsstr(xml, tag);
    if (!start) return;

    const wchar_t* attrStart = wcsstr(start, attr);
    if (!attrStart) return;

    attrStart = wcschr(attrStart, L'\'');
    if (!attrStart) return;
    attrStart++;

    const wchar_t* end = wcschr(attrStart, L'\'');
    if (!end) return;

    size_t len = end - attrStart;
    if (len >= outSize) len = outSize - 1;

    wcsncpy_s(out, outSize, attrStart, len);
}

void ExtractUsefulEventData(LPCWSTR xml)
{
    wchar_t time[128] = L"";
    wchar_t targetUser[128] = L"";
    wchar_t logonType[64] = L"";
    wchar_t failureReason[64] = L"";
    wchar_t status[64] = L"";
    wchar_t subStatus[64] = L"";
    wchar_t procName[256] = L"";
    wchar_t ip[64] = L"";

    ExtractAttributeValue(xml, L"<TimeCreated", L"SystemTime=", time, 128);
    ExtractValue(xml, L"<Data Name='TargetUserName'>", targetUser, 128);
    ExtractValue(xml, L"<Data Name='LogonType'>", logonType, 64);
    ExtractValue(xml, L"<Data Name='FailureReason'>", failureReason, 64);
    ExtractValue(xml, L"<Data Name='Status'>", status, 64);
    ExtractValue(xml, L"<Data Name='SubStatus'>", subStatus, 64);
    ExtractValue(xml, L"<Data Name='ProcessName'>", procName, 256);
    ExtractValue(xml, L"<Data Name='IpAddress'>", ip, 64);

    wprintf(L"\n[Event Code 4625 - LOGON Failed]\n");
    wprintf(L"Timestamp: %s\n", time);
    wprintf(L"User: %s\n", targetUser);
    wprintf(L"Type: %s\n", logonType);
    wprintf(L"Reason: %s | Status: %s | SubStatus: %s\n", failureReason, status, subStatus);
    wprintf(L"Process: %s\n", procName);
    wprintf(L"IP: %s\n", ip);
}

DWORD PrintEvent(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;


    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
            if (pRenderedContent)
            {
                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    ExtractUsefulEventData(pRenderedContent);



cleanup:

    if (pRenderedContent)
        free(pRenderedContent);

    return status;
}

DWORD PrintResults(EVT_HANDLE hResults)
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hEvents[MAX_ARRAY];
    DWORD dwReturned = 0;

    while (true)
    {

        if (!EvtNext(hResults, MAX_ARRAY, hEvents, INFINITE, 0, &dwReturned))
        {
            if (ERROR_NO_MORE_ITEMS != (status = GetLastError()))
            {
                wprintf(L"EvtNext failed with %lu\n", status);
            }

            goto cleanup;
        }
        printf("\n");
        printf("Found %d Login Failed\n\n\n", dwReturned);
        for (DWORD i = 0; i < dwReturned; i++)
        {
            if (ERROR_SUCCESS == (status = PrintEvent(hEvents[i])))
            {
                EvtClose(hEvents[i]);
                hEvents[i] = NULL;
            }
            else
            {
                goto cleanup;
            }
        }
    }

cleanup:

    for (DWORD i = 0; i < dwReturned; i++)
    {
        if (NULL != hEvents[i])
            EvtClose(hEvents[i]);
    }

    return status;
}
