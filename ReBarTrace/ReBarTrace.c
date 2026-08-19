/** @file
  ReBarTrace.c - UEFI Shell diagnostic tool to view ReBarDxe RAM trace log.

  Copyright (c) 2026 Antigravity Project
  SPDX-License-Identifier: MIT
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include "../ReBarDxe/include/ReBarTrace.h"

EFI_GUID gReBarTraceProtocolGuid = REBAR_TRACE_PROTOCOL_GUID;

CONST CHAR16*
GetReasonString (
  IN UINT32 Reason
  )
{
  switch (Reason) {
    case RB_REASON_NONE:                           return L"RB_REASON_NONE";
    case RB_REASON_VARIABLE_DISABLED:              return L"RB_REASON_VARIABLE_DISABLED";
    case RB_REASON_CMOS_RESET_DETECTED:            return L"RB_REASON_CMOS_RESET_DETECTED";
    case RB_REASON_HOSTBRIDGE_NOT_FOUND:           return L"RB_REASON_HOSTBRIDGE_NOT_FOUND";
    case RB_REASON_HOSTBRIDGE_OPEN_FAILED:         return L"RB_REASON_HOSTBRIDGE_OPEN_FAILED";
    case RB_REASON_HOSTBRIDGE_MULTIPLE_HANDLES:    return L"RB_REASON_HOSTBRIDGE_MULTIPLE_HANDLES";
    case RB_REASON_UNEXPECTED_NOTIFY_CALLBACK:     return L"RB_REASON_UNEXPECTED_NOTIFY_CALLBACK";
    case RB_REASON_UNEXPECTED_PREPROCESS_CALLBACK: return L"RB_REASON_UNEXPECTED_PREPROCESS_CALLBACK";
    case RB_REASON_CALLBACK_OFFSET_MISMATCH:       return L"RB_REASON_CALLBACK_OFFSET_MISMATCH";
    case RB_REASON_PARTIAL_HOOK_STATE:             return L"RB_REASON_PARTIAL_HOOK_STATE";
    case RB_REASON_ALREADY_HOOKED:                 return L"RB_REASON_ALREADY_HOOKED";
    case RB_REASON_OEM_BEGIN_ENUM_FAILED:          return L"RB_REASON_OEM_BEGIN_ENUM_FAILED";
    case RB_REASON_AMI_PROTOCOL_NOT_FOUND:         return L"RB_REASON_AMI_PROTOCOL_NOT_FOUND";
    case RB_REASON_AMI_TABLE_NULL:                 return L"RB_REASON_AMI_TABLE_NULL";
    case RB_REASON_ROOTBRIDGE_COUNT_MISMATCH:      return L"RB_REASON_ROOTBRIDGE_COUNT_MISMATCH";
    case RB_REASON_ENTRY_STATUS_MISMATCH:          return L"RB_REASON_ENTRY_STATUS_MISMATCH";
    case RB_REASON_SELECTOR_MISMATCH:              return L"RB_REASON_SELECTOR_MISMATCH";
    case RB_REASON_LENGTH_MISMATCH:                return L"RB_REASON_LENGTH_MISMATCH";
    case RB_REASON_METADATA_ALREADY_SYNCED:        return L"RB_REASON_METADATA_ALREADY_SYNCED";
    case RB_REASON_METADATA_NONZERO_BASE:          return L"RB_REASON_METADATA_NONZERO_BASE";
    case RB_REASON_GCD_LOOKUP_FAILED:              return L"RB_REASON_GCD_LOOKUP_FAILED";
    case RB_REASON_GCD_WRONG_TYPE:                 return L"RB_REASON_GCD_WRONG_TYPE";
    case RB_REASON_GCD_BASE_MISMATCH:              return L"RB_REASON_GCD_BASE_MISMATCH";
    case RB_REASON_GCD_ZERO_LENGTH:                return L"RB_REASON_GCD_ZERO_LENGTH";
    case RB_REASON_GCD_NOT_UC:                     return L"RB_REASON_GCD_NOT_UC";
    case RB_REASON_GCD_ALREADY_ALLOCATED:          return L"RB_REASON_GCD_ALREADY_ALLOCATED";
    case RB_REASON_GCD_RANGE_OVERFLOW:             return L"RB_REASON_GCD_RANGE_OVERFLOW";
    case RB_REASON_METADATA_SYNCED:                return L"RB_REASON_METADATA_SYNCED";
    default:                                       return L"UNKNOWN_REASON";
  }
}

CONST CHAR16*
GetEventName (
  IN UINT16 EventId
  )
{
  switch (EventId) {
    case RB_EVENT_ENTRY:                     return L"ENTRY";
    case RB_EVENT_TRACE_PROTOCOL_INSTALLED:  return L"TRACE_PROTOCOL_INSTALLED";
    case RB_EVENT_VARIABLE_READ:             return L"VARIABLE_READ";
    case RB_EVENT_CMOS_CHECK:                return L"CMOS_CHECK";
    case RB_EVENT_HOSTBRIDGE_FOUND:          return L"HOSTBRIDGE_FOUND";
    case RB_EVENT_HOSTBRIDGE_NOT_FOUND:      return L"HOSTBRIDGE_NOT_FOUND";
    case RB_EVENT_CALLBACK_VALIDATED:        return L"CALLBACK_VALIDATED";
    case RB_EVENT_CALLBACK_MISMATCH:         return L"CALLBACK_MISMATCH";
    case RB_EVENT_CALLBACK_OFFSET_PASS:      return L"CALLBACK_OFFSET_PASS";
    case RB_EVENT_CALLBACK_OFFSET_FAIL:      return L"CALLBACK_OFFSET_FAIL";
    case RB_EVENT_NOTIFY_HOOK_INSTALLED:     return L"NOTIFY_HOOK_INSTALLED";
    case RB_EVENT_PREPROCESS_HOOK_INSTALLED: return L"PREPROCESS_HOOK_INSTALLED";
    case RB_EVENT_BEGIN_ENUM_ENTER:          return L"BEGIN_ENUM_ENTER";
    case RB_EVENT_OEM_BEGIN_ENUM_RETURN:     return L"OEM_BEGIN_ENUM_RETURN";
    case RB_EVENT_AMI_PROTOCOL_FOUND:        return L"AMI_PROTOCOL_FOUND";
    case RB_EVENT_AMI_TABLE_FOUND:           return L"AMI_TABLE_FOUND";
    case RB_EVENT_ROOTBRIDGE_VALID:          return L"ROOTBRIDGE_VALID";
    case RB_EVENT_ROOTBRIDGE_INVALID:        return L"ROOTBRIDGE_INVALID";
    case RB_EVENT_GCD_CHECK_BEGIN:           return L"GCD_CHECK_BEGIN";
    case RB_EVENT_GCD_DESCRIPTOR:            return L"GCD_DESCRIPTOR";
    case RB_EVENT_GCD_CHECK_PASS:            return L"GCD_CHECK_PASS";
    case RB_EVENT_GCD_CHECK_FAIL:            return L"GCD_CHECK_FAIL";
    case RB_EVENT_PMEM64_BEFORE:             return L"PMEM64_BEFORE";
    case RB_EVENT_PMEM64_SYNCED:             return L"PMEM64_SYNCED";
    case RB_EVENT_PREPROCESS_ENTER:          return L"PREPROCESS_ENTER";
    case RB_EVENT_PREPROCESS_REBAR_SET:      return L"PREPROCESS_REBAR_SET";
    case RB_EVENT_PREPROCESS_REBAR_FAIL:     return L"PREPROCESS_REBAR_FAIL";
    case RB_EVENT_FEATURE_SKIPPED:           return L"FEATURE_SKIPPED";
    case RB_EVENT_FEATURE_APPLIED:           return L"FEATURE_APPLIED";
    case RB_EVENT_BEGIN_ENUM_EXIT:           return L"BEGIN_ENUM_EXIT";
    default:                                 return L"UNKNOWN_EVENT";
  }
}

CONST CHAR16*
GetSafetyStateString (
  IN UINT32 State
  )
{
  switch (State) {
    case ReBarBootSafetyStockPath:      return L"STOCK_PATH (OEM Behavior Preserved)";
    case ReBarBootSafetyFeatureSkipped: return L"FEATURE_SKIPPED (Fail-Closed, Safe Boot)";
    case ReBarBootSafetyFeatureApplied: return L"FEATURE_APPLIED (High-MMIO Synced)";
    default:                            return L"UNKNOWN_STATE";
  }
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS            Status;
  REBAR_TRACE_PROTOCOL  *Trace = NULL;
  UINTN                 Index;

  Print (L"\n================================================================================\n");
  Print (L"                          ReBarDxe Boot Safety Trace\n");
  Print (L"================================================================================\n");

  Status = gBS->LocateProtocol (&gReBarTraceProtocolGuid, NULL, (VOID **)&Trace);
  if (EFI_ERROR (Status) || Trace == NULL) {
    Print (L"[-] ReBarTraceProtocol not found (%r).\n", Status);
    Print (L"    ReBarDxe driver may not be dispatched or failed prior to protocol install.\n");
    return Status;
  }

  if (Trace->Signature != REBAR_TRACE_SIGNATURE) {
    Print (L"[-] Trace protocol signature mismatch: 0x%08X (Expected: 0x%08X)\n", Trace->Signature, REBAR_TRACE_SIGNATURE);
    return EFI_UNSUPPORTED;
  }

  Print (L"[+] Trace Protocol Located @ 0x%p (v%u)\n\n", Trace, Trace->Version);

  Print (L"Driver Execution Status:\n");
  Print (L"  Boot Safety State   : %s\n", GetSafetyStateString (Trace->BootSafetyState));
  Print (L"  Feature Armed       : %s\n", Trace->FeatureArmed ? L"YES (High-MMIO/GCD Verified)" : L"NO (GPU ReBAR Writes Blocked)");
  Print (L"  Last Reason Code    : %s (0x%X)\n", GetReasonString (Trace->LastReason), Trace->LastReason);
  Print (L"  Milestones Bitmask  : 0x%016lX\n", Trace->Milestones);
  Print (L"  Failure Bitmask     : 0x%016lX\n", Trace->FailureBitmap);
  Print (L"  Configured Size     : 2^%u MB\n", Trace->ReBarConfiguredSize);

  Print (L"\nCallbacks & Hook Verification:\n");
  Print (L"  OEM NotifyPhase     : 0x%016lX\n", Trace->OriginalNotifyPhase);
  Print (L"  Hook NotifyPhase    : 0x%016lX\n", Trace->CurrentNotifyPhase);
  Print (L"  OEM Preprocess      : 0x%016lX\n", Trace->OriginalPreprocess);
  Print (L"  Hook Preprocess     : 0x%016lX\n", Trace->CurrentPreprocess);
  Print (L"  NotifyPhase Calls   : %u\n", Trace->NotifyCallCount);
  Print (L"  Preprocess Calls    : %u\n", Trace->PreprocessCallCount);
  Print (L"  OEM BeginEnum Ret   : %r\n", Trace->OemBeginEnumerationStatus);

  Print (L"\nAMI HostBridge Metadata:\n");
  Print (L"  AMI Table Pointer   : 0x%016lX\n", Trace->AmiTable);
  Print (L"  RootBridge Count    : %u\n", Trace->RootBridgeCount);
  Print (L"  PMem64 Base (Before): 0x%016lX\n", Trace->Pmem64BaseBefore);
  Print (L"  PMem64 Base (After) : 0x%016lX\n", Trace->Pmem64BaseAfter);
  Print (L"  Sync Attempts/Pass  : %u / %u\n", Trace->SyncAttemptCount, Trace->SyncSuccessCount);

  Print (L"\nGCD High-MMIO Aperture:\n");
  Print (L"  Expected Range      : [0x%016lX, 0x%016lX)\n", Trace->GcdExpectedBase, Trace->GcdExpectedBase + Trace->GcdExpectedLength);
  Print (L"  Last Queried Base   : 0x%016lX (Len: 0x%016lX)\n", Trace->GcdLastBase, Trace->GcdLastLength);
  Print (L"  Last Queried Type   : %u (%s)\n", Trace->GcdLastType, Trace->GcdLastType == 3 ? L"MMIO" : L"Non-MMIO");
  Print (L"  Last Attributes     : 0x%016lX (UC=%s)\n", Trace->GcdLastAttributes, (Trace->GcdLastAttributes & 1) ? L"YES" : L"NO");

  Print (L"\nEvent Timeline (%u / %u entries):\n", Trace->EventCount, REBAR_TRACE_MAX_EVENTS);
  Print (L"--------------------------------------------------------------------------------\n");
  Print (L" Idx | Event Name                 | Flags  | Status             | Value         \n");
  Print (L"--------------------------------------------------------------------------------\n");

  for (Index = 0; Index < Trace->EventCount; Index++) {
    Print (L"  %02d | %-26s | 0x%04X | 0x%016lX | 0x%016lX\n",
           Index,
           GetEventName (Trace->Events[Index].EventId),
           Trace->Events[Index].Flags,
           Trace->Events[Index].Status,
           Trace->Events[Index].Value);
  }
  Print (L"================================================================================\n\n");

  return EFI_SUCCESS;
}