#include "header.h"



int main()
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL; 
    wchar_t dateFilter[64];
    GetDateOneMonthAgo(dateFilter, 64);

    wchar_t query[256];
    swprintf(query, 256, L"*[System[(EventID=4625) and TimeCreated[@SystemTime >= '%s']]]", dateFilter);

    hResults = EvtQuery(NULL, L"Security", query, EvtQueryReverseDirection);
    if (NULL == hResults)
    {
        status = GetLastError();

        if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
            wprintf(L"The channel was not found.\n");
        else if (ERROR_EVT_INVALID_QUERY == status)
            wprintf(L"The query is not valid.\n");
        else
            wprintf(L"EvtQuery failed with %lu.\n", status);
        
        return 1;
    }

    PrintResults(hResults);

    if (hResults)
        EvtClose(hResults);

    return 0;
}
