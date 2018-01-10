/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    specucheck.c

Abstract:

    This module implements a checker app for CVE-2017-5754 and CVE-2017-5715

Author:

    Alex Ionescu (@aionescu) 03-Jan-2018 - Initial version

Environment:

    User mode only.

--*/

//
// OS Headers
//
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>

//
// Internal structures and information classes
//
#define SystemSpeculationControlInformation (SYSTEM_INFORMATION_CLASS)201
typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION
{
    struct
    {
        ULONG BpbEnabled : 1;
        ULONG BpbDisabledSystemPolicy : 1;
        ULONG BpbDisabledNoHardwareSupport : 1;
        ULONG SpecCtrlEnumerated : 1;
        ULONG SpecCmdEnumerated : 1;
        ULONG IbrsPresent : 1;
        ULONG StibpPresent : 1;
        ULONG SmepPresent : 1;
        ULONG Reserved : 24;
    } SpeculationControlFlags;
} SYSTEM_SPECULATION_CONTROL_INFORMATION, *PSYSTEM_SPECULATION_CONTROL_INFORMATION;

#define SystemKernelVaShadowInformation     (SYSTEM_INFORMATION_CLASS)196
typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION
{
    struct
    {
        ULONG KvaShadowEnabled : 1;
        ULONG KvaShadowUserGlobal : 1;
        ULONG KvaShadowPcid : 1;
        ULONG KvaShadowInvpcid : 1;
        ULONG Reserved : 28;
    } KvaShadowFlags;
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, *PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;

//
// ANSI Check
//
BOOL g_SupportsAnsi;

//
// Welcome Banner
//
const WCHAR WelcomeString[] =
    L"SpecuCheck v1.0.5   --   Copyright(c) 2018 Alex Ionescu\n"
    L"https://ionescu007.github.io/SpecuCheck/  --  @aionescu\n"
    L"-------------------------------------------------------\n\n";

//
// Error String
//
const WCHAR UnpatchedString[] =
    L"Your system either does not have the appropriate patch, "
    L"or it may not support the information class required.\n";

//
// KVA Status String
//
const WCHAR g_KvaStatusString[] =
    L"%sMitigations for %sCVE-2017-5754 [rogue data cache load]%s\n"
    L"-------------------------------------------------------\n"
    L"[-] Kernel VA Shadowing Enabled:                    %s%s\n"
    L" ├───> with User Pages Marked Global:               %s%s\n"
    L" └───> with PCID Flushing Optimization (INVPCID):   %s%s\n\n";

//
// Speculation Control Status String
//
const WCHAR g_SpecControlStatusString[] =
    L"%sMitigations for %sCVE-2017-5715 [branch target injection]%s\n"
    L"-------------------------------------------------------\n"
    L"[-] Branch Prediction Mitigations Enabled:          %s%s\n"
    L" ├───> Disabled due to System Policy (Registry):    %s%s\n"
    L" └───> Disabled due to Lack of Microcode Update:    %s%s\n"
    L"[-] CPU Microcode Supports SPEC_CTRL MSR (048h):    %s%s\n"
    L" └───> Windows will use IBRS (01h):                 %s%s\n"
    L" └───> Windows will use STIPB (02h):                %s%s\n"
    L"[-] CPU Microcode Supports PRED_CMD MSR (049h):     %s%s\n"
    L" └───> Windows will use IBPB (01h):                 %s%s\n";

//
// Error codes used for clarity
//
typedef enum _SPC_ERROR_CODES
{
    SpcSuccess = 0,
    SpcFailedToOpenStandardOut = -2,
    SpcFailedToQueryKvaShadowing = -3,
    SpcFailedToQuerySpeculationControl = -4,
    SpcUnknownInfoClassFailure = -5,
} SPC_ERROR_CODES;

PCHAR
FORCEINLINE
GetResetString (
    VOID
    )
{
    return g_SupportsAnsi ? "\x1b[0m" : "";
}

PCHAR
FORCEINLINE
GetRedNoString (
    VOID
)
{
    return g_SupportsAnsi ? "\x1b[1;31m no" : " no";
}

PCHAR
FORCEINLINE
GetGreenYesString (
    VOID
    )
{
    return g_SupportsAnsi ? "\x1b[1;32myes" : "yes";
}

PCHAR
FORCEINLINE
GetRedYesString (
    VOID
)
{
    return g_SupportsAnsi ? "\x1b[1;31myes" : "yes";
}

PCHAR
FORCEINLINE
GetGreenNoString (
    VOID
)
{
    return g_SupportsAnsi ? "\x1b[1;32m no" : " no";
}

PCHAR
FORCEINLINE
GetCyanString (
    VOID
    )
{
    return g_SupportsAnsi ? "\x1b[1;36m" : "";
}

INT
SpcMain (
    VOID
    )
{
    HANDLE hStdOut;
    NTSTATUS status;
    BOOL boolResult;
    SYSTEM_KERNEL_VA_SHADOW_INFORMATION kvaInfo;
    SYSTEM_SPECULATION_CONTROL_INFORMATION specInfo;
    SPC_ERROR_CODES errorCode;
    WCHAR stateBuffer[1024];
    INT charsWritten;
	BOOL boolRedirected;

	// are we redirected?
	boolRedirected = FALSE;
	if (IsConsoleRedirected()) {
		boolRedirected = TRUE;
	}
	
	//
    // Open the output handle -- also not much we can do if this fails
    //
	if (boolRedirected) {
		hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	}
	else {
		hStdOut = CreateFile(L"CONOUT$",
			GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);
	}

	if (hStdOut == INVALID_HANDLE_VALUE)
	{
		hStdOut = INVALID_HANDLE_VALUE;
		errorCode = SpcFailedToOpenStandardOut;
		goto Exit;
	}

    //
    // Enable ANSI on Windows 10 if supported
    //
    g_SupportsAnsi = SetConsoleMode(hStdOut,
                                    ENABLE_PROCESSED_OUTPUT |
                                    ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    //
    // We now have display capabilities -- say hello!
    //
   	if (boolRedirected) {
		WriteFile(hStdOut, WelcomeString, lstrlen(WelcomeString) * sizeof(WCHAR), NULL, 0);
	}
	else {
		WriteConsole(hStdOut, WelcomeString, ARRAYSIZE(WelcomeString) - 1, NULL, NULL);
	}

    //
    // Get the KVA Shadow Information
    //
    status = NtQuerySystemInformation(SystemKernelVaShadowInformation,
                                      &kvaInfo,
                                      sizeof(kvaInfo),
                                      NULL);
    if (status == STATUS_INVALID_INFO_CLASS)
    {
        //
        // Print out an error if this failed
        //
		if (boolRedirected) {
			WriteFile(hStdOut, UnpatchedString, lstrlen(UnpatchedString) * sizeof(WCHAR), NULL, 0);
		}
		else {
			WriteConsole(hStdOut,
				UnpatchedString,
				ARRAYSIZE(UnpatchedString) - 1,
				NULL,
				NULL);
		}
        errorCode = SpcFailedToQueryKvaShadowing;
        goto Exit;
    }
    if (status == STATUS_NOT_IMPLEMENTED)
    {
        //
        // x86 Systems without the mitigation active
        //
        RtlZeroMemory(&kvaInfo, sizeof(kvaInfo));
    }
    else if (!NT_SUCCESS(status))
    {
        errorCode = SpcUnknownInfoClassFailure;
        goto Exit;
    }

    //
    // Print status of KVA Features
    //
    charsWritten = swprintf(stateBuffer,
                            ARRAYSIZE(stateBuffer),
                            g_KvaStatusString,
                            GetResetString(),
                            GetCyanString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowEnabled ?
                               GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowUserGlobal ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowPcid ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowInvpcid ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString());
   
	if (boolRedirected) {
		WriteFile(hStdOut, stateBuffer, lstrlen(stateBuffer) * sizeof(WCHAR), &charsWritten, 0);
	}
	else {
		WriteConsole(hStdOut, stateBuffer, charsWritten, NULL, NULL);
	}

    //
    // Get the Speculation Control Information
    //
    status = NtQuerySystemInformation(SystemSpeculationControlInformation,
                                      &specInfo,
                                      sizeof(specInfo),
                                      NULL);
    if (status == STATUS_INVALID_INFO_CLASS)
    {
        //
        // Print out an error if this failed
        //
        WriteConsole(hStdOut,
                     UnpatchedString,
                     ARRAYSIZE(UnpatchedString) - 1,
                     NULL,
                     NULL);
        errorCode = SpcFailedToQuerySpeculationControl;
        goto Exit;
    }
    else if (!NT_SUCCESS(status))
    {
        errorCode = SpcUnknownInfoClassFailure;
        goto Exit;
    }

    //
    // Print status of Speculation Control Features
    //
    charsWritten = swprintf(stateBuffer,
                            ARRAYSIZE(stateBuffer),
                            g_SpecControlStatusString,
                            GetResetString(),
                            GetCyanString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.BpbEnabled ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.BpbDisabledSystemPolicy ?
                                GetRedYesString() : GetGreenNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.BpbDisabledNoHardwareSupport ?
                                GetRedYesString() : GetGreenNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpecCtrlEnumerated ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.IbrsPresent ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.StibpPresent ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpecCmdEnumerated ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpecCmdEnumerated ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString());

	if (boolRedirected) {
		WriteFile(hStdOut, stateBuffer, lstrlen(stateBuffer) * sizeof(WCHAR), &charsWritten, 0);
	}
	else {
		WriteConsole(hStdOut, stateBuffer, charsWritten, NULL, NULL);
	}

    //
    // This is our happy path 
    //
    errorCode = SpcSuccess;

Exit:
    //
    // Close output handle if needed
    //
    if (hStdOut != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hStdOut);
    }

    //
    // Return the error code back to the caller, for debugging
    //
    return errorCode;
}

BOOL IsConsoleRedirected() {
	INT* stdout = GetStdHandle(STD_OUTPUT_HANDLE);
	if (stdout != INVALID_HANDLE_VALUE) {
		UINT filetype = GetFileType(stdout);
		if (!((filetype == FILE_TYPE_UNKNOWN) && (GetLastError() != ERROR_SUCCESS))) {
			DWORD mode;
			filetype &= ~(FILE_TYPE_REMOTE);
			if (filetype == FILE_TYPE_CHAR) {
				BOOL retval = GetConsoleMode(stdout,  &mode);
				if ((retval == FALSE) && (GetLastError() == ERROR_INVALID_HANDLE)) {
					return TRUE;
				}
				else {
					return FALSE;
				}
			}
			else {
				return TRUE;
			}
		}
	}

	return FALSE;
}