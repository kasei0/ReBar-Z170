#!/usr/bin/env python3
#
# Copyright (c) 2022 xCuri0 <zkqri0@gmail.com>
# SPDX-License-Identifier: MIT
#
import os
import sys
import glob
import subprocess
from pefile import PE

name = "ReBarDxe"
version = "1.0"
GUID = "a8ee1777-a4f5-4345-9da4-13742084d31e"
shell = sys.platform == "win32"
buildtype = "RELEASE"
target_arch = os.environ.get("TARGET_ARCH", "X64")
toolchain = os.environ.get("TOOL_CHAIN_TAG", "VS2022" if sys.platform == "win32" else "GCC")
if sys.platform == "win32" and "VS2022_PREFIX" not in os.environ:
    vctools = os.environ.get("VCToolsInstallDir", "")
    if vctools:
        os.environ["VS2022_PREFIX"] = vctools

def target_update(filep, p, v):
    if not os.path.exists(filep):
        return
    with open(filep, 'r') as file:
        lines = file.read()
    with open(filep, 'w') as file:
        for i, l in enumerate(lines.splitlines()):
            if l.split('=')[0].strip() == p:
                file.write(f"{p} = {v}\n")
            else:
                file.write(f"{l.rstrip()}\n")

def set_bit(data, bit):
    """Sets a specific bit."""
    return data | (1 << bit)

def set_nx_compat_flag(pe):
    """Sets the nx_compat flag to 1 in the PE/COFF file."""
    dllchar = pe.OPTIONAL_HEADER.DllCharacteristics
    dllchar = set_bit(dllchar, 8)  # 8th bit is the nx_compat_flag
    pe.OPTIONAL_HEADER.DllCharacteristics = dllchar
    return pe

if len(sys.argv) > 1:
    buildtype = sys.argv[1].upper()

# Ensure we are in EDK2 workspace root
if not os.path.exists("Conf") and os.path.exists("../../Conf"):
    os.chdir("../..")

print("TARGET: ", buildtype)
print("TARGET_ARCH: ", target_arch)
print("TOOL_CHAIN_TAG: ", toolchain)

# Update Conf/target.txt if present
if os.path.exists("./Conf/target.txt"):
    target_update("./Conf/target.txt", "TARGET", buildtype)
    target_update("./Conf/target.txt", "TARGET_ARCH", target_arch)
    if toolchain:
        target_update("./Conf/target.txt", "TOOL_CHAIN_TAG", toolchain)

# Explicitly pass target, arch, toolchain to build command
cmd = ["build", "-p", "ReBarUEFI/ReBarDxe/ReBar.dsc", "-a", target_arch, "-b", buildtype]
if toolchain:
    cmd.extend(["-t", toolchain])

print("Running:", " ".join(cmd))
subprocess.run(cmd, shell=shell, env=os.environ, stderr=sys.stderr, stdout=sys.stdout, check=True)

# Canonical Dual-Protocol DEPEX:
# PUSH gEfiPciRootBridgeIoProtocolGuid (2F707EBB-4A1A-11D4-9A38-0090273FC14D)
# PUSH gEfiPciHostBridgeResourceAllocationProtocolGuid (CF8034BE-6768-4D8B-B739-7CCE683A9FBE)
# AND (0x05)
# END (0x08)
CANONICAL_DUAL_DEPEX = bytes.fromhex("02BB7E702F1A4AD4119A380090273FC14D02BE3480CF68678B4DB7397CCE683A9FBE0508")

# 1. Locate the final released ReBarDxe.efi artifact strictly BEFORE changing working directory
# EDK2 puts the final binary directly at Build/ReBarUEFI/<BuildType>_<ToolChain>/<Arch>/ReBarDxe.efi
top_efi = os.path.normpath(f"./Build/ReBarUEFI/{buildtype}_{toolchain}/{target_arch}/ReBarDxe.efi")
if os.path.isfile(top_efi):
    rebar_matches = [top_efi]
else:
    top_matches = glob.glob(f"./Build/ReBarUEFI/{buildtype}_*/{target_arch}/ReBarDxe.efi")
    if len(top_matches) == 1:
        rebar_matches = top_matches
    else:
        all_matches = glob.glob(f"./Build/ReBarUEFI/{buildtype}_*/{target_arch}/**/ReBarDxe.efi", recursive=True)
        non_debug = [m for m in all_matches if "/DEBUG/" not in m.replace("\\", "/")]
        rebar_matches = non_debug if len(non_debug) == 1 else all_matches

if len(rebar_matches) != 1:
    raise RuntimeError(f"Artifact selection ambiguity: expected exactly 1 final ReBarDxe.efi for {buildtype}_{toolchain}/{target_arch}, found {len(rebar_matches)}: {rebar_matches}")

rebar_efi_abs = os.path.abspath(rebar_matches[0])
target_dir_abs = os.path.dirname(rebar_efi_abs)
print(f"Selected final PE artifact: {rebar_efi_abs}")

# 2. Locate compiler-generated ReBarDxe.depex strictly inside the same toolchain/arch build subtree
depex_matches = glob.glob(os.path.join(target_dir_abs, "**/ReBarDxe.depex"), recursive=True)
if len(depex_matches) != 1:
    raise RuntimeError(f"Compiler-generated ReBarDxe.depex ambiguity/missing! Expected 1 under {target_dir_abs}, found {len(depex_matches)}: {depex_matches}")

depex_file = os.path.abspath(depex_matches[0])
with open(depex_file, "rb") as f:
    depex_payload = f.read()

if depex_payload != CANONICAL_DUAL_DEPEX:
    raise RuntimeError(f"Compiler-generated DEPEX in {depex_file} ({depex_payload.hex().upper()}) does not match canonical dual-protocol DEPEX ({CANONICAL_DUAL_DEPEX.hex().upper()})! Packaging aborted.")

print(f"Compiler-generated DEPEX strictly verified matching canonical dual-protocol DEPEX from: {depex_file}")

# 3. Set NX_COMPAT flag on PE
pe = PE(rebar_efi_abs)
set_nx_compat_flag(pe)
os.remove(rebar_efi_abs)
pe.write(rebar_efi_abs)
print("PE NX_COMPAT updated.")

# 4. Build FFS in target output directory
print("Building FFS in:", target_dir_abs)
orig_dir = os.getcwd()
os.chdir(target_dir_abs)

try:
    os.remove("pe32.sec")
    os.remove("name.sec")
    os.remove("depex.sec")
    os.remove("depex.raw")
    os.remove("ReBarDxe.ffs")
except FileNotFoundError:
    pass

with open("depex.raw", "wb") as df:
    df.write(depex_payload)

efi_name = os.path.basename(rebar_efi_abs)
subprocess.run(["GenSec", "-o", "pe32.sec", efi_name, "-S", "EFI_SECTION_PE32"], shell=shell, env=os.environ, stderr=sys.stderr, stdout=sys.stdout, check=True)
subprocess.run(["GenSec", "-o", "name.sec", "-S", "EFI_SECTION_USER_INTERFACE", "-n", name], shell=shell, env=os.environ, stderr=sys.stderr, stdout=sys.stdout, check=True)
subprocess.run(["GenSec", "-o", "depex.sec", "depex.raw", "-S", "EFI_SECTION_DXE_DEPEX"], shell=shell, env=os.environ, stderr=sys.stderr, stdout=sys.stdout, check=True)
subprocess.run(["GenFfs", "-g", GUID, "-o", "ReBarDxe.ffs", "-i", "pe32.sec", "-i", "name.sec", "-i", "depex.sec", "-t", "EFI_FV_FILETYPE_DRIVER", "--checksum"], shell=shell, env=os.environ, stderr=sys.stderr, stdout=sys.stdout, check=True)

try:
    os.remove("pe32.sec")
    os.remove("name.sec")
    os.remove("depex.sec")
    os.remove("depex.raw")
except FileNotFoundError:
    pass

os.chdir(orig_dir)
print("FFS packaging complete.")
print("Finished building FFS successfully with DXE DEPEX!")