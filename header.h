#ifndef HEADER_H
#define HEADER_H

#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <sddl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdbool.h>
// Costanti
#define MAX_ARRAY 100
#define TIMEOUT 1000

#pragma comment(lib, "wevtapi.lib")


void GetDateOneMonthAgo(wchar_t* buffer, size_t bufferSize);

void ExtractValue(const wchar_t* xml, const wchar_t* tag, wchar_t* out, size_t outSize);

void ExtractAttributeValue(const wchar_t* xml, const wchar_t* tag, const wchar_t* attr, wchar_t* out, size_t outSize);

void ExtractUsefulEventData(LPCWSTR xml);

DWORD PrintEvent(EVT_HANDLE hEvent);

DWORD PrintResults(EVT_HANDLE hResults);

#endif 