/** @file
  ReBarTrace.h - Passive RAM-Only Boot-Safety Trace Protocol for ReBarDxe

  Copyright (c) 2026 Antigravity Project
  SPDX-License-Identifier: MIT
**/

#ifndef _REBAR_TRACE_H_
#define _REBAR_TRACE_H_

#include <Uefi.h>

#define REBAR_TRACE_PROTOCOL_GUID \
  { 0x4f87e81b, 0x3cb4, 0x4a92, { 0x8a, 0x19, 0xd2, 0xe4, 0x76, 0x89, 0x6e, 0x51 } }

#define REBAR_TRACE_SIGNATURE     0x52425452  // 'RBTR'
#define REBAR_TRACE_VERSION       1
#define REBAR_TRACE_MAX_EVENTS    32

// High-level Boot Safety State
typedef enum {
    ReBarBootSafetyUnknown = 0,
    ReBarBootSafetyStockPath,
    ReBarBootSafetyFeatureSkipped,
    ReBarBootSafetyFeatureApplied
} REBAR_BOOT_SAFETY_STATE;

// Reason Codes covering all fail-open and execution paths
typedef enum {
    RB_REASON_NONE = 0,
    RB_REASON_VARIABLE_DISABLED,
    RB_REASON_CMOS_RESET_DETECTED,
    RB_REASON_HOSTBRIDGE_NOT_FOUND,
    RB_REASON_HOSTBRIDGE_OPEN_FAILED,
    RB_REASON_HOSTBRIDGE_MULTIPLE_HANDLES,
    RB_REASON_UNEXPECTED_NOTIFY_CALLBACK,
    RB_REASON_UNEXPECTED_PREPROCESS_CALLBACK,
    RB_REASON_CALLBACK_OFFSET_MISMATCH,
    RB_REASON_PARTIAL_HOOK_STATE,
    RB_REASON_ALREADY_HOOKED,
    RB_REASON_OEM_BEGIN_ENUM_FAILED,
    RB_REASON_AMI_PROTOCOL_NOT_FOUND,
    RB_REASON_AMI_TABLE_NULL,
    RB_REASON_ROOTBRIDGE_COUNT_MISMATCH,
    RB_REASON_ENTRY_STATUS_MISMATCH,
    RB_REASON_SELECTOR_MISMATCH,
    RB_REASON_LENGTH_MISMATCH,
    RB_REASON_METADATA_ALREADY_SYNCED,
    RB_REASON_METADATA_NONZERO_BASE,
    RB_REASON_GCD_LOOKUP_FAILED,
    RB_REASON_GCD_WRONG_TYPE,
    RB_REASON_GCD_BASE_MISMATCH,
    RB_REASON_GCD_ZERO_LENGTH,
    RB_REASON_GCD_NOT_UC,
    RB_REASON_GCD_ALREADY_ALLOCATED,
    RB_REASON_GCD_RANGE_OVERFLOW,
    RB_REASON_METADATA_SYNCED
} REBAR_REASON_CODE;

// Trace Event IDs
typedef enum {
    RB_EVENT_ENTRY = 1,
    RB_EVENT_TRACE_PROTOCOL_INSTALLED,
    RB_EVENT_VARIABLE_READ,
    RB_EVENT_CMOS_CHECK,
    RB_EVENT_HOSTBRIDGE_FOUND,
    RB_EVENT_HOSTBRIDGE_NOT_FOUND,
    RB_EVENT_CALLBACK_VALIDATED,
    RB_EVENT_CALLBACK_MISMATCH,
    RB_EVENT_CALLBACK_OFFSET_PASS,
    RB_EVENT_CALLBACK_OFFSET_FAIL,
    RB_EVENT_NOTIFY_HOOK_INSTALLED,
    RB_EVENT_PREPROCESS_HOOK_INSTALLED,
    RB_EVENT_BEGIN_ENUM_ENTER,
    RB_EVENT_OEM_BEGIN_ENUM_RETURN,
    RB_EVENT_AMI_PROTOCOL_FOUND,
    RB_EVENT_AMI_TABLE_FOUND,
    RB_EVENT_ROOTBRIDGE_VALID,
    RB_EVENT_ROOTBRIDGE_INVALID,
    RB_EVENT_GCD_CHECK_BEGIN,
    RB_EVENT_GCD_DESCRIPTOR,
    RB_EVENT_GCD_CHECK_PASS,
    RB_EVENT_GCD_CHECK_FAIL,
    RB_EVENT_PMEM64_BEFORE,
    RB_EVENT_PMEM64_SYNCED,
    RB_EVENT_PREPROCESS_ENTER,
    RB_EVENT_PREPROCESS_REBAR_SET,
    RB_EVENT_PREPROCESS_REBAR_FAIL,
    RB_EVENT_FEATURE_SKIPPED,
    RB_EVENT_FEATURE_APPLIED,
    RB_EVENT_BEGIN_ENUM_EXIT
} REBAR_EVENT_ID;

// Fixed 16-byte event structure (64-bit Status for x64 EFI_STATUS error bits)
typedef struct {
    UINT16      EventId;
    UINT16      Flags;
    UINT32      Reserved;
    UINT64      Status;
    UINT64      Value;
} REBAR_TRACE_EVENT;

// Protocol Structure
typedef struct _REBAR_TRACE_PROTOCOL {
    UINT32                  Signature;          // 'RBTR'
    UINT16                  Version;            // 1
    UINT16                  Size;               // sizeof(REBAR_TRACE_PROTOCOL)

    UINT64                  Milestones;         // Bitmask of achieved milestones
    UINT64                  FailureBitmap;      // Bitmask of failure flags

    UINT32                  LastReason;         // REBAR_REASON_CODE
    UINT32                  BootSafetyState;    // REBAR_BOOT_SAFETY_STATE
    UINT32                  FeatureArmed;       // 1 if High-MMIO/GCD verified and GPU ReBAR writes permitted

    EFI_STATUS              EntryStatus;
    EFI_STATUS              OemBeginEnumerationStatus;

    UINT32                  NotifyCallCount;
    UINT32                  PreprocessCallCount;
    UINT32                  SyncAttemptCount;
    UINT32                  SyncSuccessCount;

    UINT64                  OriginalNotifyPhase;
    UINT64                  CurrentNotifyPhase;

    UINT64                  OriginalPreprocess;
    UINT64                  CurrentPreprocess;

    UINT64                  AmiTable;
    UINT32                  RootBridgeCount;
    UINT32                  ReBarConfiguredSize; // 2^x MB configured in ReBarState

    UINT64                  Pmem64BaseBefore;
    UINT64                  Pmem64BaseAfter;

    UINT64                  GcdExpectedBase;
    UINT64                  GcdExpectedLength;

    UINT64                  GcdLastBase;
    UINT64                  GcdLastLength;

    UINT32                  GcdLastType;
    UINT32                  Reserved2;
    UINT64                  GcdLastAttributes;  // 64-bit GCD attributes

    UINT32                  EventCount;
    UINT32                  Reserved3;

    REBAR_TRACE_EVENT       Events[REBAR_TRACE_MAX_EVENTS];
} REBAR_TRACE_PROTOCOL;

#endif