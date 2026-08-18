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

ReBarDXE = glob.glob(f"./Build/ReBarUEFI/{buildtype}_*/X64/**/ReBarDxe.efi", recursive=True)
if len(ReBarDXE) == 0:
    ReBarDXE = glob.glob(f"./Build/ReBarUEFI/**/ReBarDxe.efi", recursive=True)

if len(ReBarDXE) == 0:
    print("Build failed: no ReBarDxe.efi found in Build directory")
    sys.exit(1)

# set NX_COMPAT
pe = PE(ReBarDXE[0])
set_nx_compat_flag(pe)

os.remove(ReBarDXE[0])
pe.write(ReBarDXE[0])

print("PE output:", ReBarDXE[0])
print("Building FFS...")
orig_dir = os.getcwd()
os.chdir(os.path.dirname(ReBarDXE[0]))

try:
    os.remove("pe32.sec")
    os.remove("name.sec")
    os.remove("depex.sec")
    os.remove("ReBarDxe.ffs")
except FileNotFoundError:
    pass

# Canonical Dual-Protocol DEPEX:
# PUSH gEfiPciRootBridgeIoProtocolGuid (2F707EBB-4A1A-11D4-9A38-0090273FC14D)
# PUSH gEfiPciHostBridgeResourceAllocationProtocolGuid (CF8034BE-6768-4D8B-B739-7CCE683A9FBE)
# AND (0x05)
# END (0x08)
CANONICAL_DUAL_DEPEX = bytes.fromhex("02BB7E702F1A4AD4119A380090273FC14D02BE3480CF68678B4DB7397CCE683A9FBE0508")

# Look for compiler-generated ReBarDxe.depex strictly in the same build output tree
rebar_efi_abs = os.path.abspath(ReBarDXE[0])
target_dir_abs = os.path.dirname(rebar_efi_abs)
candidate_depex_paths = [
    os.path.join(target_dir_abs, "ReBarDxe.depex"),
    os.path.normpath(os.path.join(target_dir_abs, "..", "OUTPUT", "ReBarDxe.depex")),
    os.path.normpath(os.path.join(target_dir_abs, "..", "DEBUG", "ReBarDxe.depex"))
]

depex_payload = None
for p in candidate_depex_paths:
    if os.path.exists(p):
        with open(p, "rb") as f:
            depex_payload = f.read()
        print(f"Loaded compiler-generated depex from: {os.path.normpath(p)}")
        break

if depex_payload is None:
    print("Notice: compiler-generated depex not found in target dir; using canonical dual-protocol DEPEX.")
    depex_payload = CANONICAL_DUAL_DEPEX
else:
    if depex_payload != CANONICAL_DUAL_DEPEX:
        raise RuntimeError(f"Compiler-generated DEPEX mismatch! Found: {depex_payload.hex().upper()}, Expected: {CANONICAL_DUAL_DEPEX.hex().upper()}")
    print("Compiler-generated DEPEX strictly verified matching canonical dual-protocol DEPEX.")

with open("depex.raw", "wb") as df:
    df.write(depex_payload)

efi_name = os.path.basename(ReBarDXE[0])
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
print("Finished building FFS successfully with DXE DEPEX!")