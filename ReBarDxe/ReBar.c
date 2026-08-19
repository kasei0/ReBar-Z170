/*
Copyright (c) 2022-2023 xCuri0 <zkqri0@gmail.com>
Copyright (c) 2026 Antigravity Project
SPDX-License-Identifier: MIT
*/
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/PciRootBridgeIo.h>
#include <IndustryStandard/Pci22.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/BaseLib.h>
#include "include/pciRegs.h"
#include "include/PciHostBridgeResourceAllocation.h"
#include "include/AmiPciHostBridgeInit.h"
#include "include/ReBarTrace.h"

EFI_GUID gAmiPciHostBridgeInitProtocolGuid = AMI_PCI_HOST_BRIDGE_INIT_PROTOCOL_GUID;
EFI_GUID gReBarTraceProtocolGuid          = REBAR_TRACE_PROTOCOL_GUID;

#ifdef _MSC_VER
#pragma warning(disable:28251)
#include <intrin.h>
#pragma warning(default:28251)
#endif

#define PCI_POSSIBLE_ERROR(val) ((val) == 0xffffffff)
#define PCI_VENDOR_ID_ATI       0x1002
#define BUILD_YEAR              2023

// a3c5b77a-c88f-4a93-bf1c-4a92a32c65ce
static EFI_GUID reBarStateGuid = { 0xa3c5b77a, 0xc88f, 0x4a93, {0xbf, 0x1c, 0x4a, 0x92, 0xa3, 0x2c, 0x65, 0xce}};

// 0: disabled
// >0: maximum BAR size (2^x) set to value. UINT8_MAX for unlimited
static UINT8 reBarState = 0;

static EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *pciResAlloc = NULL;
static EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *pciRootBridgeIo = NULL;

static EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_PREPROCESS_CONTROLLER o_PreprocessController = NULL;
static EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_NOTIFY_PHASE o_NotifyPhase = NULL;

// Global RAM-Only Passive Trace Structure
static REBAR_TRACE_PROTOCOL mTrace;

static
VOID
ReBarTraceLogEvent (
  IN UINT16 EventId,
  IN UINT16 Flags,
  IN UINT32 Status,
  IN UINT64 Value
  )
{
  if (mTrace.EventCount < REBAR_TRACE_MAX_EVENTS) {
    mTrace.Events[mTrace.EventCount].EventId = EventId;
    mTrace.Events[mTrace.EventCount].Flags   = Flags;
    mTrace.Events[mTrace.EventCount].Status  = Status;
    mTrace.Events[mTrace.EventCount].Value   = Value;
    mTrace.EventCount++;
  }
}

VOID
SyncAmiPciHostBridgeMetadata (
  VOID
  )
{
  EFI_STATUS                                Status;
  VOID                                      *AmiHostBridgeInit = NULL;
  UINT8                                     *Table = NULL;
  UINT64                                    Count = 0;
  UINT32                                    EntryStatus;
  UINT32                                    Selector;
  UINT64                                    Length;
  UINT64                                    Base;
  UINT64                                    Cursor;
  UINT64                                    ExpectedEnd;
  UINT64                                    DescEnd;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR           GcdDesc;

  mTrace.SyncAttemptCount++;

  // =========================================================================
  // VALIDATION PHASE: All Read-Only Checks (Fail-Closed, Boot Fail-Open)
  // =========================================================================

  // 1. Locate AMI HostBridge Init Protocol
  Status = gBS->LocateProtocol (&gAmiPciHostBridgeInitProtocolGuid, NULL, (VOID **)&AmiHostBridgeInit);
  if (EFI_ERROR (Status) || AmiHostBridgeInit == NULL) {
    mTrace.FailureBitmap |= (1ULL << 5);
    mTrace.LastReason     = RB_REASON_AMI_PROTOCOL_NOT_FOUND;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, (UINT32)Status, RB_REASON_AMI_PROTOCOL_NOT_FOUND);
    return;
  }
  ReBarTraceLogEvent (RB_EVENT_AMI_PROTOCOL_FOUND, 0, 0, (UINT64)(UINTN)AmiHostBridgeInit);
  mTrace.Milestones |= (1ULL << 9);

  // 2. Obtain Table pointer and RootBridge Count
  Table = *(UINT8 **)((UINT8 *)AmiHostBridgeInit + AMI_PROTOCOL_TABLE_OFFSET);
  Count = *(UINT64 *)((UINT8 *)AmiHostBridgeInit + AMI_PROTOCOL_COUNT_OFFSET);
  mTrace.AmiTable         = (UINT64)(UINTN)Table;
  mTrace.RootBridgeCount  = (UINT32)Count;

  if (Table == NULL) {
    mTrace.FailureBitmap |= (1ULL << 6);
    mTrace.LastReason     = RB_REASON_AMI_TABLE_NULL;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_AMI_TABLE_NULL);
    return;
  }

  if (Count != 1) {
    mTrace.FailureBitmap |= (1ULL << 6);
    mTrace.LastReason     = RB_REASON_ROOTBRIDGE_COUNT_MISMATCH;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_ROOTBRIDGE_INVALID, 0, 0, Count);
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_ROOTBRIDGE_COUNT_MISMATCH);
    return;
  }
  ReBarTraceLogEvent (RB_EVENT_AMI_TABLE_FOUND, 0, 0, (UINT64)(UINTN)Table);
  ReBarTraceLogEvent (RB_EVENT_ROOTBRIDGE_VALID, 0, 0, Count);
  mTrace.Milestones |= (1ULL << 10);

  // 3. Read and strictly validate PMem64 compact aperture entry invariants
  EntryStatus = ReadUnaligned32 ((CONST UINT32 *)(Table + AMI_RB0_PMEM64_STATUS_OFFSET));
  Selector    = ReadUnaligned32 ((CONST UINT32 *)(Table + AMI_RB0_PMEM64_SELECTOR_OFFSET));
  Length      = ReadUnaligned64 ((CONST UINT64 *)(Table + AMI_RB0_PMEM64_LENGTH_OFFSET));
  Base        = ReadUnaligned64 ((CONST UINT64 *)(Table + AMI_RB0_PMEM64_BASE_OFFSET));
  mTrace.Pmem64BaseBefore = Base;
  ReBarTraceLogEvent (RB_EVENT_PMEM64_BEFORE, 0, 0, Base);

  if (EntryStatus != AMI_EXPECTED_STATUS_ACTIVE) {
    mTrace.FailureBitmap |= (1ULL << 7);
    mTrace.LastReason     = RB_REASON_ENTRY_STATUS_MISMATCH;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, EntryStatus, RB_REASON_ENTRY_STATUS_MISMATCH);
    return;
  }

  if (Selector != AMI_EXPECTED_SELECTOR_PMEM64) {
    mTrace.FailureBitmap |= (1ULL << 7);
    mTrace.LastReason     = RB_REASON_SELECTOR_MISMATCH;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, Selector, RB_REASON_SELECTOR_MISMATCH);
    return;
  }

  if (Length != AMI_EXPECTED_HIGH_MMIO_LENGTH) {
    mTrace.FailureBitmap |= (1ULL << 7);
    mTrace.LastReason     = RB_REASON_LENGTH_MISMATCH;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, (UINT32)Length, RB_REASON_LENGTH_MISMATCH);
    return;
  }

  // 4. Idempotent check: if already synchronized to High-MMIO Base, exit
  if (Base == AMI_EXPECTED_HIGH_MMIO_BASE) {
    mTrace.LastReason     = RB_REASON_METADATA_ALREADY_SYNCED;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureApplied;
    return;
  }

  // 5. Strict known-state check: only synchronize if Base is exactly 0 (stale uninitialized state)
  if (Base != 0) {
    mTrace.FailureBitmap |= (1ULL << 7);
    mTrace.LastReason     = RB_REASON_METADATA_NONZERO_BASE;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, (UINT32)Base, RB_REASON_METADATA_NONZERO_BASE);
    return;
  }

  // 6. Verify authoritative continuous GCD High-MMIO coverage [128GiB, 192GiB)
  Cursor      = AMI_EXPECTED_HIGH_MMIO_BASE;
  ExpectedEnd = AMI_EXPECTED_HIGH_MMIO_BASE + AMI_EXPECTED_HIGH_MMIO_LENGTH;
  ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_BEGIN, 0, 0, Cursor);

  while (Cursor < ExpectedEnd) {
    Status = gDS->GetMemorySpaceDescriptor (Cursor, &GcdDesc);
    mTrace.GcdLastBase       = GcdDesc.BaseAddress;
    mTrace.GcdLastLength     = GcdDesc.Length;
    mTrace.GcdLastType       = GcdDesc.GcdMemoryType;
    mTrace.GcdLastAttributes = (UINT32)GcdDesc.Attributes;

    if (EFI_ERROR (Status)) {
      mTrace.FailureBitmap |= (1ULL << 8);
      mTrace.LastReason     = RB_REASON_GCD_LOOKUP_FAILED;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 0, (UINT32)Status, Cursor);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, (UINT32)Status, RB_REASON_GCD_LOOKUP_FAILED);
      return;
    }

    ReBarTraceLogEvent (RB_EVENT_GCD_DESCRIPTOR, (UINT16)GcdDesc.GcdMemoryType, (UINT32)GcdDesc.Attributes, GcdDesc.BaseAddress);

    if (GcdDesc.GcdMemoryType != EfiGcdMemoryTypeMemoryMappedIo) {
      mTrace.FailureBitmap |= (1ULL << 8);
      mTrace.LastReason     = RB_REASON_GCD_WRONG_TYPE;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 1, GcdDesc.GcdMemoryType, Cursor);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, GcdDesc.GcdMemoryType, RB_REASON_GCD_WRONG_TYPE);
      return;
    }

    if (GcdDesc.BaseAddress > Cursor) {
      mTrace.FailureBitmap |= (1ULL << 8);
      mTrace.LastReason     = RB_REASON_GCD_BASE_MISMATCH;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 2, 0, GcdDesc.BaseAddress);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_GCD_BASE_MISMATCH);
      return;
    }

    if (GcdDesc.Length == 0) {
      mTrace.FailureBitmap |= (1ULL << 8);
      mTrace.LastReason     = RB_REASON_GCD_ZERO_LENGTH;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 3, 0, Cursor);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_GCD_ZERO_LENGTH);
      return;
    }

    if ((GcdDesc.Attributes & EFI_MEMORY_UC) == 0) {
      mTrace.FailureBitmap |= (1ULL << 9);
      mTrace.LastReason     = RB_REASON_GCD_NOT_UC;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 4, (UINT32)GcdDesc.Attributes, Cursor);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, (UINT32)GcdDesc.Attributes, RB_REASON_GCD_NOT_UC);
      return;
    }

    if (GcdDesc.ImageHandle != NULL) {
      mTrace.FailureBitmap |= (1ULL << 9);
      mTrace.LastReason     = RB_REASON_GCD_ALREADY_ALLOCATED;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 5, 0, (UINT64)(UINTN)GcdDesc.ImageHandle);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_GCD_ALREADY_ALLOCATED);
      return;
    }

    DescEnd = GcdDesc.BaseAddress + GcdDesc.Length;
    if (DescEnd <= Cursor || DescEnd < GcdDesc.BaseAddress) {
      mTrace.FailureBitmap |= (1ULL << 8);
      mTrace.LastReason     = RB_REASON_GCD_RANGE_OVERFLOW;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 6, 0, DescEnd);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_GCD_RANGE_OVERFLOW);
      return;
    }

    Cursor = DescEnd;
  }

  ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_PASS, 0, 0, ExpectedEnd);
  mTrace.Milestones |= (1ULL << 11);

  // =========================================================================
  // COMMIT PHASE: Single-Field Atomic Write
  // =========================================================================
  WriteUnaligned64 ((UINT64 *)(Table + AMI_RB0_PMEM64_BASE_OFFSET), AMI_EXPECTED_HIGH_MMIO_BASE);

  mTrace.Pmem64BaseAfter  = AMI_EXPECTED_HIGH_MMIO_BASE;
  mTrace.SyncSuccessCount++;
  mTrace.BootSafetyState  = ReBarBootSafetyFeatureApplied;
  mTrace.LastReason       = RB_REASON_METADATA_SYNCED;
  mTrace.Milestones      |= (1ULL << 12);

  ReBarTraceLogEvent (RB_EVENT_PMEM64_SYNCED, 0, 0, AMI_EXPECTED_HIGH_MMIO_BASE);
  ReBarTraceLogEvent (RB_EVENT_FEATURE_APPLIED, 0, 0, 0);
}

EFI_STATUS
EFIAPI
NotifyPhaseOverride (
  IN EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL *This,
  IN EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PHASE    Phase
  )
{
  EFI_STATUS Status;

  mTrace.NotifyCallCount++;
  ReBarTraceLogEvent (RB_EVENT_BEGIN_ENUM_ENTER, (UINT16)Phase, 0, 0);

  // 1. Always call OEM callback FIRST!
  Status = o_NotifyPhase (This, Phase);

  // 2. Synchronize metadata ONLY on Phase 0 (BeginEnumeration) after OEM succeeds
  if (Phase == EfiPciHostBridgeBeginEnumeration) {
    mTrace.OemBeginEnumerationStatus = Status;
    ReBarTraceLogEvent (RB_EVENT_OEM_BEGIN_ENUM_RETURN, 0, (UINT32)Status, 0);

    if (EFI_ERROR (Status)) {
      mTrace.FailureBitmap |= (1ULL << 4);
      mTrace.LastReason     = RB_REASON_OEM_BEGIN_ENUM_FAILED;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, (UINT32)Status, RB_REASON_OEM_BEGIN_ENUM_FAILED);
      return Status; // Propagate exact OEM error
    }

    mTrace.Milestones |= (1ULL << 8);
    SyncAmiPciHostBridgeMetadata ();
  }

  ReBarTraceLogEvent (RB_EVENT_BEGIN_ENUM_EXIT, (UINT16)Phase, (UINT32)Status, 0);
  return Status;
}

// find last set bit and return the index of it
INTN fls(UINT32 x)
{
    #ifdef _MSC_VER
    unsigned long r = 0;
    if (_BitScanReverse(&r, (unsigned long)x)) {
        return (INTN)r;
    }
    return -1;
    #else
    UINT32 r;
    // taken from linux x86 bitops.h
    asm("bsrl %1,%0"
	    : "=r" (r)
	    : "rm" (x), "0" (-1));
    return r;
    #endif
}

UINT64 pciAddrOffset(UINTN pciAddress, INTN offset)
{
    UINTN reg = (pciAddress & 0xffffffff00000000) >> 32;
    UINTN bus = (pciAddress & 0xff000000) >> 24;
    UINTN dev = (pciAddress & 0xff0000) >> 16;
    UINTN func = (pciAddress & 0xff00) >> 8;

    return EFI_PCI_ADDRESS(bus, dev, func, ((INT64)reg + offset));
}

// created these functions to make it easy to read as we are adapting alot of code from Linux
EFI_STATUS pciReadConfigDword(UINTN pciAddress, INTN pos, UINT32 *buf)
{
    if (pciRootBridgeIo == NULL) return EFI_DEVICE_ERROR;
    return pciRootBridgeIo->Pci.Read(pciRootBridgeIo, EfiPciWidthUint32, pciAddrOffset(pciAddress, pos), 1, buf);
}

EFI_STATUS pciWriteConfigDword(UINTN pciAddress, INTN pos, UINT32 *buf)
{
    if (pciRootBridgeIo == NULL) return EFI_DEVICE_ERROR;
    return pciRootBridgeIo->Pci.Write(pciRootBridgeIo, EfiPciWidthUint32, pciAddrOffset(pciAddress, pos), 1, buf);
}

EFI_STATUS pciReadConfigWord(UINTN pciAddress, INTN pos, UINT16 *buf)
{
    if (pciRootBridgeIo == NULL) return EFI_DEVICE_ERROR;
    return pciRootBridgeIo->Pci.Read(pciRootBridgeIo, EfiPciWidthUint16, pciAddrOffset(pciAddress, pos), 1, buf);
}

EFI_STATUS pciWriteConfigWord(UINTN pciAddress, INTN pos, UINT16 *buf)
{
    if (pciRootBridgeIo == NULL) return EFI_DEVICE_ERROR;
    return pciRootBridgeIo->Pci.Write(pciRootBridgeIo, EfiPciWidthUint16, pciAddrOffset(pciAddress, pos), 1, buf);
}

EFI_STATUS pciReadConfigByte(UINTN pciAddress, INTN pos, UINT8 *buf)
{
    if (pciRootBridgeIo == NULL) return EFI_DEVICE_ERROR;
    return pciRootBridgeIo->Pci.Read(pciRootBridgeIo, EfiPciWidthUint8, pciAddrOffset(pciAddress, pos), 1, buf);
}

EFI_STATUS pciWriteConfigByte(UINTN pciAddress, INTN pos, UINT8 *buf)
{
    if (pciRootBridgeIo == NULL) return EFI_DEVICE_ERROR;
    return pciRootBridgeIo->Pci.Write(pciRootBridgeIo, EfiPciWidthUint8, pciAddrOffset(pciAddress, pos), 1, buf);
}

// adapted from linux pci_find_ext_capability
UINT16 pciFindExtCapability(UINTN pciAddress, INTN cap)
{
    INTN ttl;
    UINT32 header;
    UINT16 pos = PCI_CFG_SPACE_SIZE;

    /* minimum 8 bytes per capability */
    ttl = (PCI_CFG_SPACE_EXP_SIZE - PCI_CFG_SPACE_SIZE) / 8;

    if (EFI_ERROR(pciReadConfigDword(pciAddress, pos, &header)))
        return 0;
    /*
     * If we have no capabilities, this is indicated by cap ID,
     * cap version and next pointer all being 0. Or it could also be all FF
     */
    if (header == 0 || PCI_POSSIBLE_ERROR(header))
        return 0;

    while (ttl-- > 0)
    {
        if (PCI_EXT_CAP_ID(header) == cap && pos != 0)
            return pos;

        pos = PCI_EXT_CAP_NEXT(header);
        if (pos < PCI_CFG_SPACE_SIZE)
            break;

        if (EFI_ERROR(pciReadConfigDword(pciAddress, pos, &header)))
            break;
    }
    return 0;
}

INTN pciRebarFindPos(UINTN pciAddress, INTN pos, UINT8 bar)
{
    UINTN nbars, i;
    UINT32 ctrl;

    if (EFI_ERROR(pciReadConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl)))
        return -1;

    nbars = (ctrl & PCI_REBAR_CTRL_NBAR_MASK) >>
            PCI_REBAR_CTRL_NBAR_SHIFT;

    for (i = 0; i < nbars; i++, pos += 8)
    {
        UINTN bar_idx;

        if (EFI_ERROR(pciReadConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl)))
            return -1;

        bar_idx = ctrl & PCI_REBAR_CTRL_BAR_IDX;
        if (bar_idx == bar)
            return pos;
    }
    return -1;
}

UINT32 pciRebarGetPossibleSizes(UINTN pciAddress, UINTN epos, UINT16 vid, UINT16 did, UINT8 bar)
{
    INTN pos;
    UINT32 cap;

    pos = pciRebarFindPos(pciAddress, (INTN)epos, bar);
    if (pos < 0)
        return 0;

    if (EFI_ERROR(pciReadConfigDword(pciAddress, pos + PCI_REBAR_CAP, &cap)))
        return 0;

    cap &= PCI_REBAR_CAP_SIZES;

    /* Sapphire RX 5600 XT Pulse has an invalid cap dword for BAR 0 */
    if (vid == PCI_VENDOR_ID_ATI && did == 0x731f &&
        bar == 0 && cap == 0x7000)
        cap = 0x3f000;

    return cap >> 4;
}

INTN pciRebarSetSize(UINTN pciAddress, UINTN epos, UINT8 bar, UINT8 size)
{
    INTN pos;
    UINT32 ctrl;

    pos = pciRebarFindPos(pciAddress, (INTN)epos, bar);
    if (pos < 0)
        return pos;

    if (EFI_ERROR(pciReadConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl)))
        return -1;

    ctrl &= (UINT32)~PCI_REBAR_CTRL_BAR_SIZE;
    ctrl |= (UINT32)size << PCI_REBAR_CTRL_BAR_SHIFT;

    pciWriteConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl);
    return 0;
}

VOID reBarSetupDevice(EFI_HANDLE handle, EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS addrInfo)
{
    UINTN epos;
    UINT16 vid, did;
    UINTN pciAddress;
    EFI_STATUS Status;

    Status = gBS->HandleProtocol(handle, &gEfiPciRootBridgeIoProtocolGuid, (void **)&pciRootBridgeIo);
    if (EFI_ERROR(Status) || pciRootBridgeIo == NULL)
        return;

    pciAddress = EFI_PCI_ADDRESS(addrInfo.Bus, addrInfo.Device, addrInfo.Function, 0);
    if (EFI_ERROR(pciReadConfigWord(pciAddress, 0, &vid)))
        return;
    if (EFI_ERROR(pciReadConfigWord(pciAddress, 2, &did)))
        return;

    if (vid == 0xFFFF || vid == 0x0000)
        return;

    DEBUG((DEBUG_INFO, "ReBarDXE: Device vid:%x did:%x\n", vid, did));

    epos = pciFindExtCapability(pciAddress, PCI_EXT_CAP_ID_REBAR);
    if (epos)
    {
        for (UINT8 bar = 0; bar < 6; bar++)
        {
            UINT32 rBarS = pciRebarGetPossibleSizes(pciAddress, epos, vid, did, bar);
            if (!rBarS)
                continue;
            // start with size from fls
            for (UINT8 n = MIN((UINT8)fls(rBarS), reBarState); n > 0; n--) {
                // check if size is supported
                if (rBarS & (1 << n)) {
                    pciRebarSetSize(pciAddress, epos, bar, n);
                    mTrace.Milestones |= (1ULL << 14);
                    ReBarTraceLogEvent (RB_EVENT_PREPROCESS_REBAR_SET, (UINT16)bar, (UINT32)n, (UINT64)vid | ((UINT64)did << 16));
                    break;
                }
            }
        }
    }
}

EFI_STATUS EFIAPI PreprocessControllerOverride (
  IN  EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL  *This,
  IN  EFI_HANDLE                                        RootBridgeHandle,
  IN  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS       PciAddress,
  IN  EFI_PCI_CONTROLLER_RESOURCE_ALLOCATION_PHASE      Phase
  )
{
    EFI_STATUS status;

    mTrace.PreprocessCallCount++;
    ReBarTraceLogEvent (RB_EVENT_PREPROCESS_ENTER, (UINT16)Phase, 0,
                        EFI_PCI_ADDRESS (PciAddress.Bus, PciAddress.Device, PciAddress.Function, 0));

    // 1. Call the original OEM method FIRST
    status = o_PreprocessController(This, RootBridgeHandle, PciAddress, Phase);

    // 2. If OEM failed, return OEM status immediately
    if (EFI_ERROR(status)) {
        return status;
    }

    // 3. Setup Resizable BAR before resource collection if enabled
    if (Phase <= EfiPciBeforeResourceCollection && reBarState > 0) {
        reBarSetupDevice(RootBridgeHandle, PciAddress);
    }

    return status;
}

VOID pciHostBridgeResourceAllocationProtocolHook()
{
    EFI_STATUS status;
    UINTN handleCount = 0;
    EFI_HANDLE *handleBuffer = NULL;
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_PREPROCESS_CONTROLLER OrigPreprocess;
    EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PROTOCOL_NOTIFY_PHASE OrigNotify;

    status = gBS->LocateHandleBuffer(
        ByProtocol,
        &gEfiPciHostBridgeResourceAllocationProtocolGuid,
        NULL,
        &handleCount,
        &handleBuffer);

    if (EFI_ERROR(status) || handleBuffer == NULL) {
        mTrace.FailureBitmap |= (1ULL << 2);
        mTrace.LastReason     = RB_REASON_HOSTBRIDGE_NOT_FOUND;
        mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
        ReBarTraceLogEvent (RB_EVENT_HOSTBRIDGE_NOT_FOUND, 0, (UINT32)status, 0);
        goto free;
    }

    if (handleCount != 1) {
        mTrace.FailureBitmap |= (1ULL << 2);
        mTrace.LastReason     = RB_REASON_HOSTBRIDGE_MULTIPLE_HANDLES;
        mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
        ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, (UINT32)handleCount, RB_REASON_HOSTBRIDGE_MULTIPLE_HANDLES);
        goto free;
    }

    status = gBS->OpenProtocol(
        handleBuffer[0],
        &gEfiPciHostBridgeResourceAllocationProtocolGuid,
        (VOID **)&pciResAlloc,
        gImageHandle,
        NULL,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL);

    if (EFI_ERROR(status) || pciResAlloc == NULL) {
        mTrace.FailureBitmap |= (1ULL << 2);
        mTrace.LastReason     = RB_REASON_HOSTBRIDGE_OPEN_FAILED;
        mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
        ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, (UINT32)status, RB_REASON_HOSTBRIDGE_OPEN_FAILED);
        goto free;
    }

    ReBarTraceLogEvent (RB_EVENT_HOSTBRIDGE_FOUND, 0, 0, (UINT64)(UINTN)pciResAlloc);
    mTrace.Milestones |= (1ULL << 3);

    OrigPreprocess = pciResAlloc->PreprocessController;
    OrigNotify     = pciResAlloc->NotifyPhase;

    if (OrigPreprocess == NULL || OrigNotify == NULL) {
        mTrace.FailureBitmap |= (1ULL << 3);
        mTrace.LastReason     = RB_REASON_UNEXPECTED_NOTIFY_CALLBACK;
        mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
        ReBarTraceLogEvent (RB_EVENT_CALLBACK_MISMATCH, 0, 0, 0);
        goto free;
    }

    if (OrigPreprocess == &PreprocessControllerOverride || OrigNotify == &NotifyPhaseOverride) {
        mTrace.LastReason     = RB_REASON_ALREADY_HOOKED;
        ReBarTraceLogEvent (RB_EVENT_CALLBACK_VALIDATED, 1, 0, 0);
        goto free;
    }

    ReBarTraceLogEvent (RB_EVENT_CALLBACK_VALIDATED, 0, 0, 0);
    mTrace.Milestones |= (1ULL << 4);

    DEBUG((DEBUG_INFO, "ReBarDXE: Hooking EfiPciHostBridgeResourceAllocationProtocol\n"));

    // =========================================================================
    // COMMIT HOOKS ATOMICALLY
    // =========================================================================
    o_PreprocessController            = OrigPreprocess;
    o_NotifyPhase                     = OrigNotify;
    pciResAlloc->PreprocessController = &PreprocessControllerOverride;
    pciResAlloc->NotifyPhase          = &NotifyPhaseOverride;

    mTrace.OriginalNotifyPhase        = (UINT64)(UINTN)OrigNotify;
    mTrace.CurrentNotifyPhase         = (UINT64)(UINTN)&NotifyPhaseOverride;
    mTrace.OriginalPreprocess         = (UINT64)(UINTN)OrigPreprocess;
    mTrace.CurrentPreprocess          = (UINT64)(UINTN)&PreprocessControllerOverride;
    mTrace.Milestones                |= (1ULL << 5);

    ReBarTraceLogEvent (RB_EVENT_NOTIFY_HOOK_INSTALLED, 0, 0, (UINT64)(UINTN)&NotifyPhaseOverride);
    ReBarTraceLogEvent (RB_EVENT_PREPROCESS_HOOK_INSTALLED, 0, 0, (UINT64)(UINTN)&PreprocessControllerOverride);

free:
    if (handleBuffer != NULL) {
        FreePool(handleBuffer);
    }
}

EFI_STATUS EFIAPI rebarInit(
    IN EFI_HANDLE imageHandle,
    IN EFI_SYSTEM_TABLE *systemTable)
{
    UINTN bufferSize = 1;
    EFI_STATUS status;
    UINT32 attributes;
    EFI_TIME time;

    // 1. Initialize fixed-size passive trace protocol state
    ZeroMem (&mTrace, sizeof (REBAR_TRACE_PROTOCOL));
    mTrace.Signature        = REBAR_TRACE_SIGNATURE;
    mTrace.Version          = REBAR_TRACE_VERSION;
    mTrace.Size             = sizeof (REBAR_TRACE_PROTOCOL);
    mTrace.BootSafetyState  = ReBarBootSafetyStockPath;
    mTrace.GcdExpectedBase  = AMI_EXPECTED_HIGH_MMIO_BASE;
    mTrace.GcdExpectedLength= AMI_EXPECTED_HIGH_MMIO_LENGTH;
    mTrace.LastReason       = RB_REASON_NONE;
    mTrace.Milestones       = (1ULL << 0); // Bit 0: Entry reached

    ReBarTraceLogEvent (RB_EVENT_ENTRY, 0, 0, 0);

    // 2. Install optional passive RAM-Only Trace Protocol (non-fatal, boot fail-open)
    status = gBS->InstallProtocolInterface (
                    &imageHandle,
                    &gReBarTraceProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mTrace
                    );
    if (!EFI_ERROR (status)) {
        mTrace.Milestones |= (1ULL << 6);
        ReBarTraceLogEvent (RB_EVENT_TRACE_PROTOCOL_INSTALLED, 0, (UINT32)status, 0);
    }
    mTrace.EntryStatus = status;

    DEBUG((DEBUG_INFO, "ReBarDXE: Loaded\n"));

    // 3. Read ReBarState variable
    status = gRT->GetVariable(L"ReBarState", &reBarStateGuid,
        &attributes,
        &bufferSize, &reBarState);

    // any attempts to overflow reBarState should result in EFI_BUFFER_TOO_SMALL
    if (status != EFI_SUCCESS) {
        reBarState = 0;
    }

    mTrace.ReBarConfiguredSize = reBarState;
    ReBarTraceLogEvent (RB_EVENT_VARIABLE_READ, 0, (UINT32)status, reBarState);

    if (reBarState == 0) {
        mTrace.LastReason      = RB_REASON_VARIABLE_DISABLED;
        mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
        ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_VARIABLE_DISABLED);
        return EFI_SUCCESS; // Fail-open: continue normal boot
    }

    mTrace.Milestones |= (1ULL << 1);
    DEBUG((DEBUG_INFO, "ReBarDXE: Enabled, maximum BAR size 2^%u MB\n", reBarState));

    // 4. Detect CMOS reset by checking if year is before BUILD_YEAR
    status = gRT->GetTime (&time, NULL);
    if (!EFI_ERROR (status) && time.Year < BUILD_YEAR) {
        reBarState = 0;
        bufferSize = 1;
        attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;

        gRT->SetVariable(L"ReBarState", &reBarStateGuid,
            attributes,
            bufferSize, &reBarState);

        mTrace.FailureBitmap  |= (1ULL << 1);
        mTrace.LastReason      = RB_REASON_CMOS_RESET_DETECTED;
        mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
        ReBarTraceLogEvent (RB_EVENT_CMOS_CHECK, 1, 0, time.Year);
        ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_CMOS_RESET_DETECTED);
        return EFI_SUCCESS; // Fail-open: continue normal boot
    }

    mTrace.Milestones |= (1ULL << 2);
    ReBarTraceLogEvent (RB_EVENT_CMOS_CHECK, 0, 0, time.Year);

    // 5. For overriding PciHostBridgeResourceAllocationProtocol
    pciHostBridgeResourceAllocationProtocolHook();

    return EFI_SUCCESS; // Always return EFI_SUCCESS to guarantee unblocked boot
}