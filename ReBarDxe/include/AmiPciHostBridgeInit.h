/** @file
  Minimal, proven offsets for AMI PCI Host Bridge Init Protocol metadata synchronization.
  
  Reverse engineered from GA-Z170X-Gaming 3 BIOS F22j:
  - AmiBoardInfo2: RVA 0x9E8 (Protocol->Table allocation in RAM), RVA 0xAB0 (InstallMultipleProtocolInterfaces)
  - PciHostBridge: sub_2FB0 (Protocol Interface load), sub_3004 (GCD consumption)
  - PciBus: sub_7D34 (Platform aperture policy enforcement), sub_89BC (Resource allocation dispatcher)
**/

#ifndef _AMI_PCI_HOST_BRIDGE_INIT_H_
#define _AMI_PCI_HOST_BRIDGE_INIT_H_

#include <Uefi.h>

///
/// Protocol GUID from F22j PciHostBridge sub_2FB0 / AmiBoardInfo2
/// {4FC0733F-6FD2-491B-A890-5374521BF48F}
/// Raw bytes in memory: 3F 73 C0 4F D2 6F 1B 49 A8 90 53 74 52 1B F4 8F
///
#define AMI_PCI_HOST_BRIDGE_INIT_PROTOCOL_GUID \
  { 0x4FC0733F, 0x6FD2, 0x491B, { 0xA8, 0x90, 0x53, 0x74, 0x52, 0x1B, 0xF4, 0x8F } }

extern EFI_GUID gAmiPciHostBridgeInitProtocolGuid;

///
/// Protocol Interface offsets (AmiBoardInfo2: rdx+0x10 = PciData / Table)
///
#define AMI_PROTOCOL_TABLE_OFFSET         0x10
#define AMI_PCIDATA_SIGNATURE_STRING      "$PCIDATA"
#define AMI_PCIDATA_SIGNATURE_LENGTH      8

///
/// RootBridge 0 proven compact PMem64 entry.
/// P = TableBase + 0x20
/// Entry4 start = P + 0xC5
///   Status   +0x00 -> Table + 0xE5
///   Selector +0x04 -> Table + 0xE9
///   Base     +0x08 -> Table + 0xED
///   Length   +0x10 -> Table + 0xF5
///
#define AMI_RB0_PMEM64_STATUS_OFFSET      0xE5  // UINT32 (Compact Aperture Status, Expected 1)
#define AMI_RB0_PMEM64_SELECTOR_OFFSET    0xE9  // UINT32 (Compact Aperture Selector, 0x24 = PMem64)
#define AMI_RB0_PMEM64_BASE_OFFSET        0xED  // UINT64 (Compact Aperture BaseAddress, Stale 0)
#define AMI_RB0_PMEM64_LENGTH_OFFSET      0xF5  // UINT64 (Compact Aperture Length, 64GiB)

///
/// Expected platform constants in F22j Above4G state
///
#define AMI_EXPECTED_STATUS_ACTIVE        0x00000001
#define AMI_EXPECTED_SELECTOR_PMEM64      0x00000024
#define AMI_EXPECTED_HIGH_MMIO_BASE       0x2000000000ULL // 128 GiB
#define AMI_EXPECTED_HIGH_MMIO_LENGTH     0x1000000000ULL // 64 GiB

#endif // _AMI_PCI_HOST_BRIDGE_INIT_H_
