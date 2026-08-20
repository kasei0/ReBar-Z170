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
#include <Library/BaseMemoryLib.h>
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
#define TARGET_GPU_DEVICE_ID    0x7551
#define BUILD_YEAR              2023

// F22j OEM PciHostBridge Callback RVA offsets
#define OEM_NOTIFY_PHASE_RVA          0x1718ULL
#define OEM_PREPROCESS_CONTROLLER_RVA 0x22B8ULL
#define OEM_CALLBACK_DELTA_RVA        (OEM_PREPROCESS_CONTROLLER_RVA - OEM_NOTIFY_PHASE_RVA) // 0xBA0

// a3c5b77a-c88f-4a93-bf1c-4a92a32c65ce
static EFI_GUID reBarStateGuid = { 0xa3c5b77a, 0xc88f, 0x4a93, {0xbf, 0x1c, 0x4a, 0x92, 0xa3, 0x2c, 0x65, 0xce}};

// 0: disabled
// >0: maximum BAR size (2^x) set to value. UINT8_MAX for unlimited
static UINT8 reBarState = 0;

// Hardware Feature Gate: only TRUE after High-MMIO and GCD are 100% verified
static BOOLEAN mFeatureArmed = FALSE;

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
  IN UINT64 Status,
  IN UINT64 Value
  )
{
  if (mTrace.EventCount < REBAR_TRACE_MAX_EVENTS) {
    mTrace.Events[mTrace.EventCount].EventId  = EventId;
    mTrace.Events[mTrace.EventCount].Flags    = Flags;
    mTrace.Events[mTrace.EventCount].Reserved = 0;
    mTrace.Events[mTrace.EventCount].Status   = Status;
    mTrace.Events[mTrace.EventCount].Value    = Value;
    mTrace.EventCount++;
  }
}

BOOLEAN
SyncAmiPciHostBridgeMetadata (
  VOID
  )
{
  EFI_STATUS                                Status;
  VOID                                      *AmiHostBridgeInit = NULL;
  UINT8                                     *Table = NULL;
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
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, Status, RB_REASON_AMI_PROTOCOL_NOT_FOUND);
    return FALSE;
  }
  ReBarTraceLogEvent (RB_EVENT_AMI_PROTOCOL_FOUND, 0, 0, (UINT64)(UINTN)AmiHostBridgeInit);
  mTrace.Milestones |= (1ULL << 9);

  // 2. Obtain Table pointer ($PCIDATA) and strictly validate signature
  Table = *(UINT8 **)((UINT8 *)AmiHostBridgeInit + AMI_PROTOCOL_TABLE_OFFSET);
  mTrace.AmiTable         = (UINT64)(UINTN)Table;
  mTrace.RootBridgeCount  = 1;

  if (Table == NULL || CompareMem (Table, AMI_PCIDATA_SIGNATURE_STRING, AMI_PCIDATA_SIGNATURE_LENGTH) != 0) {
    mTrace.FailureBitmap |= (1ULL << 6);
    mTrace.LastReason     = RB_REASON_AMI_TABLE_NULL;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_AMI_TABLE_NULL);
    return FALSE;
  }
  ReBarTraceLogEvent (RB_EVENT_AMI_TABLE_FOUND, 0, 0, (UINT64)(UINTN)Table);
  ReBarTraceLogEvent (RB_EVENT_ROOTBRIDGE_VALID, 0, 0, 1);
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
    return FALSE;
  }

  if (Selector != AMI_EXPECTED_SELECTOR_PMEM64) {
    mTrace.FailureBitmap |= (1ULL << 7);
    mTrace.LastReason     = RB_REASON_SELECTOR_MISMATCH;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, Selector, RB_REASON_SELECTOR_MISMATCH);
    return FALSE;
  }

  if (Length != AMI_EXPECTED_HIGH_MMIO_LENGTH) {
    mTrace.FailureBitmap |= (1ULL << 7);
    mTrace.LastReason     = RB_REASON_LENGTH_MISMATCH;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, Length, RB_REASON_LENGTH_MISMATCH);
    return FALSE;
  }

  // 4. Strict Base validation: Base must be EITHER 0 (uninitialized) OR 128G (already synced)
  if (Base != 0 && Base != AMI_EXPECTED_HIGH_MMIO_BASE) {
    mTrace.FailureBitmap |= (1ULL << 7);
    mTrace.LastReason     = RB_REASON_METADATA_NONZERO_BASE;
    mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
    ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, Base, RB_REASON_METADATA_NONZERO_BASE);
    return FALSE;
  }

  // 5. Verify authoritative continuous GCD High-MMIO coverage [128GiB, 192GiB) (MANDATORY for both Base==0 and Base==128G!)
  Cursor      = AMI_EXPECTED_HIGH_MMIO_BASE;
  ExpectedEnd = AMI_EXPECTED_HIGH_MMIO_BASE + AMI_EXPECTED_HIGH_MMIO_LENGTH;
  ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_BEGIN, 0, 0, Cursor);

  while (Cursor < ExpectedEnd) {
    ZeroMem (&GcdDesc, sizeof (GcdDesc));
    Status = gDS->GetMemorySpaceDescriptor (Cursor, &GcdDesc);

    // PI/EDK2 rule: Check Status FIRST before reading GcdDesc fields!
    if (EFI_ERROR (Status)) {
      mTrace.FailureBitmap |= (1ULL << 8);
      mTrace.LastReason     = RB_REASON_GCD_LOOKUP_FAILED;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 0, Status, Cursor);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, Status, RB_REASON_GCD_LOOKUP_FAILED);
      return FALSE;
    }

    // Now safely record verified GcdDesc fields
    mTrace.GcdLastBase       = GcdDesc.BaseAddress;
    mTrace.GcdLastLength     = GcdDesc.Length;
    mTrace.GcdLastType       = GcdDesc.GcdMemoryType;
    mTrace.GcdLastAttributes = GcdDesc.Attributes;

    ReBarTraceLogEvent (RB_EVENT_GCD_DESCRIPTOR, (UINT16)GcdDesc.GcdMemoryType, GcdDesc.Attributes, GcdDesc.BaseAddress);

    if (GcdDesc.GcdMemoryType != EfiGcdMemoryTypeMemoryMappedIo) {
      mTrace.FailureBitmap |= (1ULL << 8);
      mTrace.LastReason     = RB_REASON_GCD_WRONG_TYPE;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 1, GcdDesc.GcdMemoryType, Cursor);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, GcdDesc.GcdMemoryType, RB_REASON_GCD_WRONG_TYPE);
      return FALSE;
    }

    if (GcdDesc.BaseAddress > Cursor) {
      mTrace.FailureBitmap |= (1ULL << 8);
      mTrace.LastReason     = RB_REASON_GCD_BASE_MISMATCH;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 2, 0, GcdDesc.BaseAddress);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_GCD_BASE_MISMATCH);
      return FALSE;
    }

    if (GcdDesc.Length == 0) {
      mTrace.FailureBitmap |= (1ULL << 8);
      mTrace.LastReason     = RB_REASON_GCD_ZERO_LENGTH;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 3, 0, Cursor);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_GCD_ZERO_LENGTH);
      return FALSE;
    }

    if ((GcdDesc.Attributes & EFI_MEMORY_UC) == 0) {
      mTrace.FailureBitmap |= (1ULL << 9);
      mTrace.LastReason     = RB_REASON_GCD_NOT_UC;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 4, GcdDesc.Attributes, Cursor);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, GcdDesc.Attributes, RB_REASON_GCD_NOT_UC);
      return FALSE;
    }

    if (GcdDesc.ImageHandle != NULL) {
      mTrace.FailureBitmap |= (1ULL << 9);
      mTrace.LastReason     = RB_REASON_GCD_ALREADY_ALLOCATED;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 5, 0, (UINT64)(UINTN)GcdDesc.ImageHandle);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_GCD_ALREADY_ALLOCATED);
      return FALSE;
    }

    DescEnd = GcdDesc.BaseAddress + GcdDesc.Length;
    if (DescEnd <= Cursor || DescEnd < GcdDesc.BaseAddress) {
      mTrace.FailureBitmap |= (1ULL << 8);
      mTrace.LastReason     = RB_REASON_GCD_RANGE_OVERFLOW;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_FAIL, 6, 0, DescEnd);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_GCD_RANGE_OVERFLOW);
      return FALSE;
    }

    Cursor = DescEnd;
  }

  ReBarTraceLogEvent (RB_EVENT_GCD_CHECK_PASS, 0, 0, ExpectedEnd);
  mTrace.Milestones |= (1ULL << 11);

  // =========================================================================
  // COMMIT PHASE: Write only if Base == 0; If already 128G, skip write
  // =========================================================================
  if (Base == 0) {
    WriteUnaligned64 ((UINT64 *)(Table + AMI_RB0_PMEM64_BASE_OFFSET), AMI_EXPECTED_HIGH_MMIO_BASE);
    mTrace.Pmem64BaseAfter  = AMI_EXPECTED_HIGH_MMIO_BASE;
    mTrace.LastReason       = RB_REASON_METADATA_SYNCED;
    ReBarTraceLogEvent (RB_EVENT_PMEM64_SYNCED, 0, 0, AMI_EXPECTED_HIGH_MMIO_BASE);
  } else {
    mTrace.Pmem64BaseAfter  = Base;
    mTrace.LastReason       = RB_REASON_METADATA_ALREADY_SYNCED;
  }

  mTrace.SyncSuccessCount++;
  mTrace.BootSafetyState  = ReBarBootSafetyFeatureApplied;
  mTrace.Milestones      |= (1ULL << 12);
  ReBarTraceLogEvent (RB_EVENT_FEATURE_APPLIED, 0, 0, 0);

  return TRUE;
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

  // 1. Immediately disarm feature gate BEFORE calling OEM on BeginEnumeration
  //    Eliminates any possible stale-armed window across multiple phases or reconnects
  if (Phase == EfiPciHostBridgeBeginEnumeration) {
    mFeatureArmed = FALSE;
  }

  // 2. Call OEM callback
  Status = o_NotifyPhase (This, Phase);

  // 3. Fail-open: If ANY OEM NotifyPhase returns error, ensure feature gate stays disarmed
  if (EFI_ERROR (Status)) {
    mFeatureArmed = FALSE;
    mTrace.FeatureArmed = 0;
    if (Phase == EfiPciHostBridgeBeginEnumeration) {
      mTrace.OemBeginEnumerationStatus = Status;
      mTrace.FailureBitmap |= (1ULL << 4);
      mTrace.LastReason     = RB_REASON_OEM_BEGIN_ENUM_FAILED;
      mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
      ReBarTraceLogEvent (RB_EVENT_OEM_BEGIN_ENUM_RETURN, 0, Status, 0);
      ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, Status, RB_REASON_OEM_BEGIN_ENUM_FAILED);
    }
    ReBarTraceLogEvent (RB_EVENT_BEGIN_ENUM_EXIT, (UINT16)Phase, Status, 0);
    return Status;
  }

  // 4. Synchronize metadata ONLY on Phase 0 (BeginEnumeration) after OEM succeeded
  if (Phase == EfiPciHostBridgeBeginEnumeration) {
    mTrace.OemBeginEnumerationStatus = Status;
    ReBarTraceLogEvent (RB_EVENT_OEM_BEGIN_ENUM_RETURN, 0, Status, 0);
    mTrace.Milestones |= (1ULL << 8);

    // Arm feature gate ONLY if metadata + GCD are 100% verified
    mFeatureArmed = SyncAmiPciHostBridgeMetadata ();
    mTrace.FeatureArmed = mFeatureArmed ? 1 : 0;
  }

  ReBarTraceLogEvent (RB_EVENT_BEGIN_ENUM_EXIT, (UINT16)Phase, Status, 0);
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
    EFI_STATUS status;

    pos = pciRebarFindPos(pciAddress, (INTN)epos, bar);
    if (pos < 0)
        return pos;

    if (EFI_ERROR(pciReadConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl)))
        return -1;

    ctrl &= (UINT32)~PCI_REBAR_CTRL_BAR_SIZE;
    ctrl |= (UINT32)size << PCI_REBAR_CTRL_BAR_SHIFT;

    // Write-then-Read-Back Verification
    status = pciWriteConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl);
    if (EFI_ERROR(status))
        return -1;

    ctrl = 0;
    if (EFI_ERROR(pciReadConfigDword(pciAddress, pos + PCI_REBAR_CTRL, &ctrl)))
        return -1;

    if (((ctrl & PCI_REBAR_CTRL_BAR_SIZE) >> PCI_REBAR_CTRL_BAR_SHIFT) != (UINT32)size)
        return -1; // Write verify failed

    return 0;
}

VOID reBarSetupDevice(EFI_HANDLE handle, EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS addrInfo)
{
    UINTN epos;
    UINT16 vid = 0, did = 0;
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

    // Safety Candidate Restriction: Strictly mutate ONLY target AMD Radeon AI PRO R9700 (1002:7551)
    if (vid != PCI_VENDOR_ID_ATI || did != TARGET_GPU_DEVICE_ID)
        return;

    DEBUG((DEBUG_INFO, "ReBarDXE: Target GPU detected vid:%04x did:%04x\n", vid, did));

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
                    if (pciRebarSetSize(pciAddress, epos, bar, n) == 0) {
                        mTrace.Milestones |= (1ULL << 14);
                        ReBarTraceLogEvent (RB_EVENT_PREPROCESS_REBAR_SET, (UINT16)bar, (UINT64)n, (UINT64)vid | ((UINT64)did << 16));
                    } else {
                        ReBarTraceLogEvent (RB_EVENT_PREPROCESS_REBAR_FAIL, (UINT16)bar, (UINT64)n, (UINT64)vid | ((UINT64)did << 16));
                    }
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

    // Increment call count for every invocation
    mTrace.PreprocessCallCount++;

    // 1. Call the original OEM method FIRST
    status = o_PreprocessController(This, RootBridgeHandle, PciAddress, Phase);

    // 2. If OEM failed, return OEM status immediately
    if (EFI_ERROR(status)) {
        return status;
    }

    // 3. Setup Resizable BAR ONLY IF:
    //    a) Phase is before resource collection
    //    b) reBarState > 0
    //    c) High-MMIO / GCD validation was 100% SUCCESSFUL (mFeatureArmed == TRUE)
    if (Phase <= EfiPciBeforeResourceCollection && reBarState > 0 && mFeatureArmed) {
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
    UINT64 CallbackDelta;

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
        ReBarTraceLogEvent (RB_EVENT_HOSTBRIDGE_NOT_FOUND, 0, status, 0);
        goto free;
    }

    if (handleCount != 1) {
        mTrace.FailureBitmap |= (1ULL << 2);
        mTrace.LastReason     = RB_REASON_HOSTBRIDGE_MULTIPLE_HANDLES;
        mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
        ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, handleCount, RB_REASON_HOSTBRIDGE_MULTIPLE_HANDLES);
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
        ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, status, RB_REASON_HOSTBRIDGE_OPEN_FAILED);
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

    // Check if ALREADY hooked by another instance of ReBarDxe
    if (OrigPreprocess == &PreprocessControllerOverride && OrigNotify == &NotifyPhaseOverride) {
        mTrace.LastReason     = RB_REASON_ALREADY_HOOKED;
        ReBarTraceLogEvent (RB_EVENT_CALLBACK_VALIDATED, 1, 0, 0);
        goto free;
    }

    if (OrigPreprocess == &PreprocessControllerOverride || OrigNotify == &NotifyPhaseOverride) {
        mTrace.FailureBitmap |= (1ULL << 3);
        mTrace.LastReason     = RB_REASON_PARTIAL_HOOK_STATE;
        mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
        ReBarTraceLogEvent (RB_EVENT_CALLBACK_MISMATCH, 1, 0, 0);
        goto free;
    }

    // Strict OEM Callback RVA Delta Validation for Z170 F22j:
    // OrigPreprocess (0x22B8) - OrigNotify (0x1718) == 0xBA0
    CallbackDelta = (UINT64)(UINTN)OrigPreprocess - (UINT64)(UINTN)OrigNotify;
    if (CallbackDelta != OEM_CALLBACK_DELTA_RVA) {
        mTrace.FailureBitmap |= (1ULL << 3);
        mTrace.LastReason     = RB_REASON_CALLBACK_OFFSET_MISMATCH;
        mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
        ReBarTraceLogEvent (RB_EVENT_CALLBACK_OFFSET_FAIL, 0, CallbackDelta, OEM_CALLBACK_DELTA_RVA);
        ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, CallbackDelta, RB_REASON_CALLBACK_OFFSET_MISMATCH);
        goto free;
    }

    ReBarTraceLogEvent (RB_EVENT_CALLBACK_OFFSET_PASS, 0, 0, CallbackDelta);
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
    UINT16 traceYear = 0;
    VOID *existingTrace = NULL;

    // 1. Anti-Duplicate Detection: Check if Trace Protocol is already installed in system
    status = gBS->LocateProtocol (&gReBarTraceProtocolGuid, NULL, &existingTrace);
    if (!EFI_ERROR (status) && existingTrace != NULL) {
        // Another instance of ReBarDxe is already active
        return EFI_SUCCESS;
    }

    // 2. Initialize fixed-size passive trace protocol state
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

    // 3. Install optional passive RAM-Only Trace Protocol (non-fatal, boot fail-open)
    status = gBS->InstallProtocolInterface (
                    &imageHandle,
                    &gReBarTraceProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mTrace
                    );
    if (!EFI_ERROR (status)) {
        mTrace.Milestones |= (1ULL << 6);
        ReBarTraceLogEvent (RB_EVENT_TRACE_PROTOCOL_INSTALLED, 0, status, 0);
    }
    mTrace.EntryStatus = status;

    DEBUG((DEBUG_INFO, "ReBarDXE: Loaded\n"));

    // 4. Read ReBarState variable
    status = gRT->GetVariable(L"ReBarState", &reBarStateGuid,
        &attributes,
        &bufferSize, &reBarState);

    // any attempts to overflow reBarState should result in EFI_BUFFER_TOO_SMALL
    if (status != EFI_SUCCESS) {
        reBarState = 0;
    }

    mTrace.ReBarConfiguredSize = reBarState;
    ReBarTraceLogEvent (RB_EVENT_VARIABLE_READ, 0, status, reBarState);

    if (reBarState == 0) {
        mTrace.LastReason      = RB_REASON_VARIABLE_DISABLED;
        mTrace.BootSafetyState = ReBarBootSafetyFeatureSkipped;
        ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_VARIABLE_DISABLED);
        return EFI_SUCCESS; // Fail-open: continue normal boot
    }

    mTrace.Milestones |= (1ULL << 1);
    DEBUG((DEBUG_INFO, "ReBarDXE: Enabled, maximum BAR size 2^%u MB\n", reBarState));

    // 5. Detect CMOS reset by checking if year is before BUILD_YEAR
    ZeroMem (&time, sizeof (time));
    status = gRT->GetTime (&time, NULL);
    traceYear = EFI_ERROR (status) ? 0 : time.Year;

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
        ReBarTraceLogEvent (RB_EVENT_CMOS_CHECK, 1, 0, traceYear);
        ReBarTraceLogEvent (RB_EVENT_FEATURE_SKIPPED, 0, 0, RB_REASON_CMOS_RESET_DETECTED);
        return EFI_SUCCESS; // Fail-open: continue normal boot
    }

    mTrace.Milestones |= (1ULL << 2);
    ReBarTraceLogEvent (RB_EVENT_CMOS_CHECK, 0, 0, traceYear);

    // 6. For overriding PciHostBridgeResourceAllocationProtocol
    pciHostBridgeResourceAllocationProtocolHook();

    return EFI_SUCCESS; // Always return EFI_SUCCESS to guarantee unblocked boot
}