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
#include <wchar.h>

//
// Internal structures and information classes
//
#pragma warning(push)
#pragma warning(disable:4214)
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
        ULONG SpeculativeStoreBypassDisableAvailable : 1;
        ULONG SpeculativeStoreBypassDisableSupported : 1;
        ULONG SpeculativeStoreBypassDisabledSystemWide : 1;
        ULONG SpeculativeStoreBypassDisabledKernel : 1;
        ULONG SpeculativeStoreBypassDisableRequired : 1;
        ULONG BpbDisabledKernelToUser : 1;
        ULONG SpecCtrlRetpolineEnabled : 1;
        ULONG SpecCtrlImportOptimizationEnabled : 1;
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
        ULONG KvaShadowRequired : 1;
        ULONG KvaShadowRequiredAvailable : 1;
        ULONG InvalidPteBit : 6;
        ULONG L1DataCacheFlushSupported : 1;
        ULONG L1TerminalFaultMitigationPresent : 1;
        ULONG Reserved : 18;
    } KvaShadowFlags;
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, *PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;
#pragma warning(pop)

//
// ANSI Check
//
BOOL g_SupportsAnsi;

//
// Welcome Banner
//
const WCHAR WelcomeString[] =
    L"SpecuCheck v1.1.0    --   Copyright(c) 2018 Alex Ionescu\n"
    L"https://ionescu007.github.io/SpecuCheck/  --   @aionescu\n"
    L"--------------------------------------------------------\n\n";

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
    L"--------------------------------------------------------\n"
    L"[-] Kernel VA Shadowing Enabled:                    %s%s\n"
    L" ├───> Unnecessary due lack of CPU vulnerability:   %s%s\n"
    L" ├───> With User Pages Marked Global:               %s%s\n"
    L" ├───> With PCID Support:                           %s%s\n"
    L" └───> With PCID Flushing Optimization (INVPCID):   %s%s\n\n";

//
// L1Tf Status String
//
const WCHAR g_L1tfStatusString[] =
    L"%sMitigations for %sCVE-2018-3620 [L1 terminal fault]%s\n"
    L"--------------------------------------------------------\n"
    L"[-] L1TF Mitigation Enabled:                        %s%s\n"
    L" ├───> Unnecessary due lack of CPU vulnerability:   %s%s\n"
    L" ├───> CPU Microcode Supports Data Cache Flush:     %s%s\n"
    L" └───> With KVA Shadow and Invalid PTE Bit:         %s%s\n\n";

//
// Speculation Control Status String
//
const WCHAR g_SpecControlStatusString[] =
    L"%sMitigations for %sCVE-2017-5715 [branch target injection]%s\n"
    L"--------------------------------------------------------\n"
    L"[-] Branch Prediction Mitigations Enabled:          %s%s\n"
    L" ├───> Disabled due to System Policy (Registry):    %s%s\n"
    L" ├───> Disabled due to Lack of Microcode Update:    %s%s\n"
    L" └───> Disabled for kernel to user transitions:     %s%s\n"
    L"[-] Branch Prediction Mitigations Optimized:        %s%s\n"
    L" └───> With Import Address Table Optimization:      %s%s\n"
    L"[-] CPU Microcode Supports SPEC_CTRL MSR (048h):    %s%s\n"
    L" ├───> Windows will use IBRS (01h):                 %s%s\n"
    L" └───> Windows will use STIPB (02h):                %s%s\n"
    L"[-] CPU Microcode Supports PRED_CMD MSR (049h):     %s%s\n"
    L" └───> Windows will use IBPB (01h):                 %s%s\n\n";

//
// Speculation Control (2) Status String
//
const WCHAR g_SpecControlStatusString2[] =
    L"%sMitigations for %sCVE-2018-3639 [speculative store bypass]%s\n"
    L"--------------------------------------------------------\n"
    L"[-] SSBD Mitigations Enabled:                       %s%s\n"
    L" ├───> Disabled due to lack of OS Support:          %s%s\n"
    L" ├───> Disabled due to lack of Microcode Update:    %s%s\n"
    L" ├───> Enabled for system-wide transitions:         %s%s\n"
    L" └───> Enabled for kernel-mode transitions only:    %s%s\n";

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
    return g_SupportsAnsi ? "\x1b[1;31m no" : " no (undesirable)";
}

PCHAR
FORCEINLINE
GetGreenYesString (
    VOID
    )
{
    return g_SupportsAnsi ? "\x1b[1;32myes" : "yes (desirable)";
}

PCHAR
FORCEINLINE
GetRedYesString (
    VOID
)
{
    return g_SupportsAnsi ? "\x1b[1;31myes" : "yes (undesirable)";
}

PCHAR
FORCEINLINE
GetGreenNoString (
    VOID
)
{
    return g_SupportsAnsi ? "\x1b[1;32m no" : " no (desirable)";
}

PCHAR
FORCEINLINE
GetCyanString (
    VOID
    )
{
    return g_SupportsAnsi ? "\x1b[1;36m" : "";
}

BOOL
IsConsoleRedirected(void);

INT
SpcMain (
    VOID
    )
{
    HANDLE hStdOut;
    NTSTATUS status;
    SYSTEM_KERNEL_VA_SHADOW_INFORMATION kvaInfo;
    SYSTEM_SPECULATION_CONTROL_INFORMATION specInfo;
    SPC_ERROR_CODES errorCode;
    WCHAR stateBuffer[2048];
    INT charsWritten;
	DWORD dwBytesWritten;
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
    SetConsoleTitle(L"SpecuCheck v1.1.0");

    //
    // We now have display capabilities -- say hello!
    //
   	if (boolRedirected) {
		WriteFile(hStdOut, WelcomeString, lstrlen(WelcomeString) * sizeof(WCHAR), &dwBytesWritten, NULL);
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
			WriteFile(hStdOut, UnpatchedString, lstrlen(UnpatchedString) * sizeof(WCHAR), &dwBytesWritten, NULL);
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
                            ((kvaInfo.KvaShadowFlags.KvaShadowEnabled) ||
                             ((kvaInfo.KvaShadowFlags.KvaShadowRequiredAvailable) &&
                              !(kvaInfo.KvaShadowFlags.KvaShadowRequired))) ?
                               GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            ((kvaInfo.KvaShadowFlags.KvaShadowRequiredAvailable) &&
                             !(kvaInfo.KvaShadowFlags.KvaShadowRequired)) ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowUserGlobal ?
                                GetRedYesString() : GetGreenNoString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowPcid ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowInvpcid ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString());
   
	if (boolRedirected) {
		WriteFile(hStdOut, stateBuffer, lstrlen(stateBuffer) * sizeof(WCHAR), &dwBytesWritten, NULL);
	}
	else {
		WriteConsole(hStdOut, stateBuffer, charsWritten, NULL, NULL);
	}

    //
    // Print status of L1TF Features
    //
    charsWritten = swprintf(stateBuffer,
                            ARRAYSIZE(stateBuffer),
                            g_L1tfStatusString,
                            GetResetString(),
                            GetCyanString(),
                            GetResetString(),
                            ((kvaInfo.KvaShadowFlags.L1TerminalFaultMitigationPresent) ||
                              ((kvaInfo.KvaShadowFlags.KvaShadowEnabled) &&
                               (kvaInfo.KvaShadowFlags.InvalidPteBit))) ? 
                               GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            ((kvaInfo.KvaShadowFlags.KvaShadowRequiredAvailable) &&
                             !(kvaInfo.KvaShadowFlags.KvaShadowRequired)) ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.L1DataCacheFlushSupported ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            ((kvaInfo.KvaShadowFlags.KvaShadowEnabled) &&
                             (kvaInfo.KvaShadowFlags.InvalidPteBit)) ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString());
    if (boolRedirected) {
		WriteFile(hStdOut, stateBuffer, lstrlen(stateBuffer) * sizeof(WCHAR), &dwBytesWritten, NULL);
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
		if (boolRedirected) {
			WriteFile(hStdOut, UnpatchedString, lstrlen(UnpatchedString) * sizeof(WCHAR), &dwBytesWritten, NULL);
		}
		else {
			WriteConsole(hStdOut,
				UnpatchedString,
				ARRAYSIZE(UnpatchedString) - 1,
				NULL,
				NULL);
		}
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
                            specInfo.SpeculationControlFlags.BpbDisabledNoHardwareSupport ?
                                GetRedYesString() : GetGreenNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.BpbDisabledKernelToUser ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpecCtrlRetpolineEnabled ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpecCtrlImportOptimizationEnabled ?
                                GetGreenYesString() : GetRedNoString(),
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
		WriteFile(hStdOut, stateBuffer, lstrlen(stateBuffer) * sizeof(WCHAR), &dwBytesWritten, NULL);
	}
	else {
		WriteConsole(hStdOut, stateBuffer, charsWritten, NULL, NULL);
	}

    //
    // Print status of Speculation Control SSBD Features
    //
    charsWritten = swprintf(stateBuffer,
                            ARRAYSIZE(stateBuffer),
                            g_SpecControlStatusString2,
                            GetResetString(),
                            GetCyanString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpeculativeStoreBypassDisableAvailable &&
                            (specInfo.SpeculationControlFlags.SpeculativeStoreBypassDisableSupported ||
                             !specInfo.SpeculationControlFlags.SpeculativeStoreBypassDisableRequired) ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            !specInfo.SpeculationControlFlags.SpeculativeStoreBypassDisableAvailable ?
                                GetRedYesString() : GetGreenNoString(),
                            GetResetString(),
                            !specInfo.SpeculationControlFlags.SpeculativeStoreBypassDisableSupported ?
                                GetRedYesString() : GetGreenNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpeculativeStoreBypassDisabledSystemWide ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpeculativeStoreBypassDisabledKernel ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString());
	if (boolRedirected) {
		WriteFile(hStdOut, stateBuffer, lstrlen(stateBuffer) * sizeof(WCHAR), &dwBytesWritten, NULL);
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
	INT* stdouthndl = GetStdHandle(STD_OUTPUT_HANDLE);
	if (stdouthndl != INVALID_HANDLE_VALUE) {
		UINT filetype = GetFileType(stdouthndl);
		if (!((filetype == FILE_TYPE_UNKNOWN) && (GetLastError() != ERROR_SUCCESS))) {
			DWORD mode;
			filetype &= ~(FILE_TYPE_REMOTE);
			if (filetype == FILE_TYPE_CHAR) {
				BOOL retval = GetConsoleMode(stdouthndl,  &mode);
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