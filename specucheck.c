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
// Welcome Banner
//
const WCHAR WelcomeString[] = L"\x1b[0mSpecuCheck v1.0.3   --   Copyright(c) 2018 Alex Ionescu\n"
                              L"\x1b[0mhttps://ionescu007.github.io/SpecuCheck/  --  @aionescu\n"
                              L"\x1b[0m-------------------------------------------------------\n\n";

//
// Error String
//
const WCHAR UnpatchedString[] = L"Your system either does not have the appropriate patch, "
                                L"or it may not support the information class required.\n";

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

    //
    // Open the output handle -- also not much we can do if this fails
    //
    hStdOut = CreateFile(L"CONOUT$",
                         GENERIC_WRITE,
                         0,
                         NULL,
                         OPEN_EXISTING,
                         0,
                         NULL);
    if (hStdOut == INVALID_HANDLE_VALUE)
    {
        hStdOut = INVALID_HANDLE_VALUE;
        errorCode = SpcFailedToOpenStandardOut;
        goto Exit;
    }

    //
    // Enable ANSI on Windows 10 if supported
    //
    SetConsoleMode(hStdOut, ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    //
    // We now have display capabilities -- say hello!
    //
    WriteConsole(hStdOut, WelcomeString, ARRAYSIZE(WelcomeString) - 1, NULL, NULL);

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
        WriteConsole(hStdOut,
                     UnpatchedString,
                     ARRAYSIZE(UnpatchedString) - 1,
                     NULL,
                     NULL);
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
                            L"\x1b[0mMitigations for \x1b[1;36mCVE-2017-5754 [rogue data cache load]\n"
                            L"\x1b[0m-------------------------------------------------------\n"
                            L"\x1b[0m[-] Kernel VA Shadowing Enabled:                    %s\n"
                            L"\x1b[0m ├───> with User Pages Marked Global:               %s\n"
                            L"\x1b[0m ├───> with PCID Support:                           %s\n"
                            L"\x1b[0m └───> with INVPCID Support:                        %s\n\n",
                            kvaInfo.KvaShadowFlags.KvaShadowEnabled ? "\x1b[1;32myes" : "\x1b[1;31m no",
                            kvaInfo.KvaShadowFlags.KvaShadowUserGlobal ? "\x1b[1;32myes" : "\x1b[1;31m no",
                            kvaInfo.KvaShadowFlags.KvaShadowPcid ? "\x1b[1;32myes" : "\x1b[1;31m no",
                            kvaInfo.KvaShadowFlags.KvaShadowInvpcid ? "\x1b[1;32myes" : "\x1b[1;31m no");
    WriteConsole(hStdOut, stateBuffer, charsWritten, NULL, NULL);

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
                            L"\x1b[0mMitigations for \x1b[1;36mCVE-2017-5715 [branch target injection]\n"
                            L"\x1b[0m-------------------------------------------------------\n"
                            L"\x1b[0m[-] Branch Prediction Mitigations Enabled:          %s\n"
                            L"\x1b[0m ├───> Disabled due to System Policy:               %s\n"
                            L"\x1b[0m └───> Disabled due to No Hardware Support:         %s\n"
                            L"\x1b[0m[-] CPU Supports Speculation Control MSR:           %s\n"
                            L"\x1b[0m └───> IBRS  Speculation Control MSR Enabled:       %s\n"
                            L"\x1b[0m[-] CPU Supports Speculation Command MSR:           %s\n"
                            L"\x1b[0m └───> STIBP Speculation Command MSR Enabled:       %s\n\x1b[0m",
                            specInfo.SpeculationControlFlags.BpbEnabled ? "\x1b[1;32myes" : "\x1b[1;31m no",
                            specInfo.SpeculationControlFlags.BpbDisabledSystemPolicy ? "\x1b[1;31myes" : "\x1b[1;32m no",
                            specInfo.SpeculationControlFlags.BpbDisabledNoHardwareSupport ? "\x1b[1;31myes" : "\x1b[1;32m no",
                            specInfo.SpeculationControlFlags.SpecCtrlEnumerated ? "\x1b[1;32myes" : "\x1b[1;31m no",
                            specInfo.SpeculationControlFlags.SpecCmdEnumerated ? "\x1b[1;32myes" : "\x1b[1;31m no",
                            specInfo.SpeculationControlFlags.IbrsPresent ? "\x1b[1;32myes" : "\x1b[1;31m no",
                            specInfo.SpeculationControlFlags.StibpPresent ? "\x1b[1;32myes" : "\x1b[1;31m no");
    WriteConsole(hStdOut, stateBuffer, charsWritten, NULL, NULL);

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
