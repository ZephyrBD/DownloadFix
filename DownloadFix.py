#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DownloadFix - a local compatibility adjuster for PCL

Usage
----
    python DownloadFix.py                  # process the PCL exe in the current directory
    python DownloadFix.py <exe> [options]

    -o FILE     output file (default "<name> (Patched).exe")
    --force     overwrite an existing output file
    --inspect   print analysis only, do not modify anything
    --cs-url    URL of the helper source (PatchModpack.cs)

Notes
----
* Personal use only. Use at your own risk.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import struct
import subprocess
import tempfile
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_EXE = HERE / "Plain Craft Launcher 2.exe"

CS_URL = "https://raw.githubusercontent.com/ZephyrBD/DownloadFix/main/PatchModpack.cs"
WORK_DIR = Path(tempfile.gettempdir()) / "pcl_patch_build"

class PatchError(RuntimeError):
    pass

class PEImage:
    def __init__(self, data: bytes) -> None:
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PatchError("not a valid PE file")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise PatchError("PE signature not found")
        nsec = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        self.magic = struct.unpack_from("<H", data, opt)[0]
        self.dd = opt + (96 if self.magic == 0x10B else 112)
        self.sections: list[tuple[int, int, int, int]] = []
        sec = opt + opt_size
        for i in range(nsec):
            row = sec + i * 40
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, row + 8)
            self.sections.append((va, max(vsize, rawsize), rawptr, rawsize))

    def rva(self, rva: int) -> int:
        for va, span, rawptr, rawsize in self.sections:
            if va <= rva < va + span:
                off = rawptr + (rva - va)
                if off >= len(self.data):
                    raise PatchError("RVA 0x%X points outside the file" % rva)
                return off
        raise PatchError("RVA 0x%X is not within any section" % rva)

class Metadata:
    def __init__(self, data: bytes, pe: PEImage) -> None:
        self.data = data
        self.pe = pe
        clr_rva, clr_size = struct.unpack_from("<II", data, pe.dd + 14 * 8)
        if not clr_rva:
            raise PatchError("not a managed assembly")
        clr = pe.rva(clr_rva)
        md_rva, md_size = struct.unpack_from("<II", data, clr + 8)
        root = pe.rva(md_rva)
        if data[root:root + 4] != b"BSJB":
            raise PatchError("invalid metadata signature")
        ver_len = struct.unpack_from("<I", data, root + 12)[0]
        p = root + 16 + ((ver_len + 3) & ~3)
        self.version_string = data[root + 16:root + 16 + ver_len].rstrip(b"\0").decode("latin1")
        nstreams = struct.unpack_from("<H", data, p + 2)[0]
        p += 4
        self.streams: dict[str, tuple[int, int]] = {}
        for _ in range(nstreams):
            off, size = struct.unpack_from("<II", data, p)
            p += 8
            end = data.index(b"\0", p)
            name = data[p:end].decode("ascii")
            p = (end + 1 + 3) & ~3
            self.streams[name] = (root + off, size)

        if "#~" not in self.streams:
            raise PatchError("only uncompressed #~ metadata streams are supported")
        ts, _ = self.streams["#~"]
        heap_sizes = data[ts + 6]
        self.str4 = bool(heap_sizes & 1)
        self.guid4 = bool(heap_sizes & 2)
        self.blob4 = bool(heap_sizes & 4)
        valid, _sorted = struct.unpack_from("<QQ", data, ts + 8)
        p = ts + 24
        self.rows: dict[int, int] = {}
        for tid in range(64):
            if valid >> tid & 1:
                self.rows[tid] = struct.unpack_from("<I", data, p)[0]
                p += 4
        self.row_sizes = {tid: self._row_size(tid) for tid in self.rows}
        self.table_off: dict[int, int] = {}
        for tid in sorted(self.rows):
            self.table_off[tid] = p
            p += self.rows[tid] * self.row_sizes[tid]

    # -- 大小计算 ------------------------------------------------------
    def _col_size(self, kind: str) -> int:
        if kind == "u8":
            return 1
        if kind == "u16":
            return 2
        if kind == "u32":
            return 4
        if kind == "str":
            return 4 if self.str4 else 2
        if kind == "guid":
            return 4 if self.guid4 else 2
        if kind == "blob":
            return 4 if self.blob4 else 2
        if kind.startswith("rid:"):
            tid = int(kind[4:], 16)
            return 4 if self.rows.get(tid, 0) > 0xFFFF else 2
        if kind.startswith("coded:"):
            name = kind[6:]
            bits, tids = CODED[name]
            limit = 1 << (16 - bits)
            return 4 if max(self.rows.get(t, 0) for t in tids) >= limit else 2
        raise PatchError("unknown column kind %s" % kind)

    def _row_size(self, tid: int) -> int:
        return sum(self._col_size(k) for k, _ in TABLES[tid])
        
    def row(self, tid: int, rid: int) -> dict[str, int]:
        base = self.table_off[tid] + (rid - 1) * self.row_sizes[tid]
        out: dict[str, int] = {}
        p = base
        for kind, name in TABLES[tid]:
            size = self._col_size(kind)
            out[name] = int.from_bytes(self.data[p:p + size], "little")
            p += size
        return out

    def string(self, idx: int) -> str:
        base, _ = self.streams.get("#Strings", (0, 0))
        if not idx:
            return ""
        end = self.data.index(b"\0", base + idx)
        return self.data[base + idx:end].decode("utf-8", "replace")

    def blob(self, idx: int) -> bytes:
        base, _ = self.streams.get("#Blob", (0, 0))
        if not idx:
            return b""
        n, p = self._compressed(base + idx)
        return self.data[p:p + n]

    def user_string(self, token: int) -> str:
        base, size = self.streams.get("#US", (0, 0))
        if not base or (token >> 24) != 0x70:
            return ""
        p = base + (token & 0xFFFFFF)
        if p >= base + size or p >= len(self.data):
            return ""
        try:
            n, p = self._compressed(p)
        except IndexError:
            return ""
        raw = self.data[p:p + n]
        if len(raw) % 2 == 1:
            raw = raw[:-1]
        return raw.decode("utf-16-le", "replace")

    def _compressed(self, p: int) -> tuple[int, int]:
        b = self.data[p]
        if b & 0x80 == 0:
            return b, p + 1
        if b & 0xC0 == 0x80:
            return ((b & 0x3F) << 8) | self.data[p + 1], p + 2
        return (((b & 0x1F) << 24) | (self.data[p + 1] << 16)
                | (self.data[p + 2] << 8) | self.data[p + 3]), p + 4

    def typedefs(self) -> list[tuple[int, str, str]]:
        return [(rid, self.string(self.row(0x02, rid)["Name"]),
                 self.string(self.row(0x02, rid)["Namespace"]))
                for rid in range(1, self.rows.get(0x02, 0) + 1)]

    def find_typedef(self, name: str, namespace: str | None = "PCL") -> list[int]:
        hits = []
        for rid, nm, ns in self.typedefs():
            if nm == name and (namespace is None or ns == namespace):
                hits.append(rid)
        if not hits and namespace is not None:
            hits = [rid for rid, nm, ns in self.typedefs() if nm == name]
        return hits

    def method_range(self, tdid: int) -> tuple[int, int]:
        start = self.row(0x02, tdid)["MethodList"]
        end = self.rows.get(0x06, 0) + 1
        for rid in range(tdid + 1, self.rows.get(0x02, 0) + 1):
            nxt = self.row(0x02, rid)["MethodList"]
            if nxt > start:
                end = nxt
                break
        return start, end

    def find_method(self, type_name: str, method_name: str) -> tuple[int, int]:
        for tdid in self.find_typedef(type_name):
            a, b = self.method_range(tdid)
            for mid in range(a, b):
                if self.string(self.row(0x06, mid)["Name"]) == method_name:
                    return mid, tdid
        raise PatchError("method not found: %s::%s" % (type_name, method_name))

    def field_in_type(self, type_name: str, field_name: str) -> tuple[int, int]:
        for tdid in self.find_typedef(type_name):
            start = self.row(0x02, tdid)["FieldList"]
            end = self.rows.get(0x04, 0) + 1
            for rid in range(tdid + 1, self.rows.get(0x02, 0) + 1):
                nxt = self.row(0x02, rid)["FieldList"]
                if nxt > start:
                    end = nxt
                    break
            for fid in range(start, end):
                if self.string(self.row(0x04, fid)["Name"]) == field_name:
                    return fid, tdid
        raise PatchError("field not found: %s::%s" % (type_name, field_name))

    def const_bool(self, type_name: str, field_name: str) -> bool | None:
        try:
            fid, _ = self.field_in_type(type_name, field_name)
        except PatchError:
            return None
        for rid in range(1, self.rows.get(0x0B, 0) + 1):
            r = self.row(0x0B, rid)
            parent = r["Parent"]
            if (parent & 3) == 0 and (parent >> 2) == fid:
                v = self.blob(r["Value"])
                if v:
                    return v[0] != 0
        return None

    def method_body(self, mid: int) -> tuple[int, int]:
        rva = self.row(0x06, mid)["RVA"]
        if rva == 0:
            return 0, 0
        off = self.pe.rva(rva)
        b = self.data[off]
        if b & 3 == 2:                       # tiny
            return off + 1, b >> 2
        hdr = struct.unpack_from("<H", self.data, off)[0]
        hs = (hdr >> 12) * 4
        size = struct.unpack_from("<I", self.data, off + 4)[0]
        if hs < 12:
            raise PatchError("bad method header (RVA 0x%X)" % rva)
        return off + hs, size


TABLES: dict[int, list[tuple[str, str]]] = {
    0x00: [("u16", "Generation"), ("str", "Name"), ("guid", "Mvid"),
           ("guid", "EncId"), ("guid", "EncBaseId")],
    0x01: [("coded:ResolutionScope", "ResolutionScope"), ("str", "Name"),
           ("str", "Namespace")],
    0x02: [("u32", "Flags"), ("str", "Name"), ("str", "Namespace"),
           ("coded:TypeDefOrRef", "Extends"), ("rid:0x04", "FieldList"),
           ("rid:0x06", "MethodList")],
    0x03: [("rid:0x04", "Field")],
    0x04: [("u16", "Flags"), ("str", "Name"), ("blob", "Signature")],
    0x05: [("rid:0x06", "Method")],
    0x06: [("u32", "RVA"), ("u16", "ImplFlags"), ("u16", "Flags"),
           ("str", "Name"), ("blob", "Signature"), ("rid:0x08", "ParamList")],
    0x07: [("rid:0x08", "Param")],
    0x08: [("u16", "Flags"), ("u16", "Sequence"), ("str", "Name")],
    0x09: [("rid:0x02", "Class"), ("coded:TypeDefOrRef", "Interface")],
    0x0A: [("coded:MemberRefParent", "Class"), ("str", "Name"),
           ("blob", "Signature")],
    0x0B: [("u16", "Type"), ("coded:HasConstant", "Parent"), ("blob", "Value")],
    0x0C: [("coded:HasCustomAttribute", "Parent"),
           ("coded:CustomAttributeType", "Type"), ("blob", "Value")],
    0x0D: [("coded:HasFieldMarshal", "Parent"), ("blob", "NativeType")],
    0x0E: [("u16", "Action"), ("coded:HasDeclSecurity", "Parent"),
           ("blob", "PermissionSet")],
    0x0F: [("u16", "PackingSize"), ("u32", "ClassSize"), ("rid:0x02", "Parent")],
    0x10: [("u32", "Offset"), ("rid:0x04", "Field")],
    0x11: [("blob", "Signature")],
    0x12: [("rid:0x02", "Parent"), ("rid:0x14", "EventList")],
    0x13: [("rid:0x14", "Event")],
    0x14: [("u16", "EventFlags"), ("str", "Name"),
           ("coded:TypeDefOrRef", "EventType")],
    0x15: [("rid:0x02", "Parent"), ("rid:0x17", "PropertyList")],
    0x16: [("rid:0x17", "Property")],
    0x17: [("u16", "Flags"), ("str", "Name"), ("blob", "Type")],
    0x18: [("u16", "Semantics"), ("rid:0x06", "Method"),
           ("coded:HasSemantics", "Association")],
    0x19: [("rid:0x02", "Class"), ("coded:MethodDefOrRef", "MethodBody"),
           ("coded:MethodDefOrRef", "MethodDeclaration")],
    0x1A: [("str", "Name")],
    0x1B: [("blob", "Signature")],
    0x1C: [("u16", "MappingFlags"), ("coded:MemberForwarded", "MemberForwarded"),
           ("str", "ImportName"), ("rid:0x1A", "ImportScope")],
    0x1D: [("u32", "RVA"), ("rid:0x04", "Field")],
    0x20: [("u32", "HashAlgId"), ("u16", "Major"), ("u16", "Minor"),
           ("u16", "Build"), ("u16", "Revision"), ("u32", "Flags"),
           ("blob", "PublicKey"), ("str", "Name"), ("str", "Culture")],
    0x21: [("u32", "Processor")],
    0x22: [("u32", "OSPlatformID"), ("u32", "OSMajor"), ("u32", "OSMinor")],
    0x23: [("u16", "Major"), ("u16", "Minor"), ("u16", "Build"),
           ("u16", "Revision"), ("u32", "Flags"), ("blob", "PublicKeyOrToken"),
           ("str", "Name"), ("str", "Culture"), ("blob", "HashValue")],
    0x24: [("u32", "Processor"), ("rid:0x23", "AssemblyRef")],
    0x25: [("u32", "OSPlatformID"), ("u32", "OSMajor"), ("u32", "OSMinor"),
           ("rid:0x23", "AssemblyRef")],
    0x26: [("u32", "Flags"), ("str", "Name"), ("blob", "HashValue")],
    0x27: [("u32", "Flags"), ("u32", "TypeDefId"), ("str", "TypeName"),
           ("str", "TypeNamespace"), ("coded:Implementation", "Implementation")],
    0x28: [("u32", "Offset"), ("u32", "Flags"), ("str", "Name"),
           ("coded:Implementation", "Implementation")],
    0x29: [("rid:0x02", "NestedClass"), ("rid:0x02", "EnclosingClass")],
    0x2A: [("u16", "Number"), ("u16", "Flags"),
           ("coded:TypeOrMethodDef", "Owner"), ("str", "Name")],
    0x2B: [("coded:MethodDefOrRef", "Method"), ("blob", "Instantiation")],
    0x2C: [("rid:0x2A", "Owner"), ("coded:TypeDefOrRef", "Constraint")],
}

CODED: dict[str, tuple[int, list[int]]] = {
    "TypeDefOrRef": (2, [0x02, 0x01, 0x1B]),
    "HasConstant": (2, [0x04, 0x08, 0x17]),
    "HasCustomAttribute": (5, [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A,
                               0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B,
                               0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B]),
    "HasFieldMarshal": (1, [0x04, 0x08]),
    "HasDeclSecurity": (2, [0x02, 0x06, 0x20]),
    "MemberRefParent": (3, [0x02, 0x01, 0x1A, 0x06, 0x1B]),
    "HasSemantics": (1, [0x14, 0x17]),
    "MethodDefOrRef": (1, [0x06, 0x0A]),
    "MemberForwarded": (1, [0x04, 0x06]),
    "Implementation": (2, [0x26, 0x23, 0x27]),
    "CustomAttributeType": (3, [0x06, 0x0A]),
    "ResolutionScope": (2, [0x00, 0x1A, 0x23, 0x01]),
    "TypeOrMethodDef": (1, [0x02, 0x06]),
}

LOADER_PATTERN = re.compile(
    rb"\x72...."                 # ldstr
    rb"\x7e...."                 # ldsfld
    rb"\x2c."                    # brfalse.s
    rb"\x7e...."                 # ldsfld
    rb"\x2b."                    # br.s
    rb"\x7e...."                 # ldsfld
    rb"\xfe\x06...."             # ldftn
    rb"\x73...."                 # newobj Func
    rb"\x25"                     # dup
    rb"\x80...."                 # stsfld
    rb"\x14"                     # ldnull
    rb"\x18"                     # ldc.i4.2
    rb"\x73....",                # newobj LoaderTask
    re.S,
)

NOP_LEN = 43
PATCH_LEN = NOP_LEN + 5


class Target:

    def __init__(self, meta: Metadata) -> None:
        self.meta = meta
        self.mid, self.tdid = meta.find_method("PageDownloadInstall", "LoaderInit")
        self.code_off, self.code_size = meta.method_body(self.mid)
        self.il = meta.data[self.code_off:self.code_off + self.code_size]
        self.fid, _ = meta.field_in_type("ModDownload", "DlClientListLoader")
        self.field_token = 0x04000000 | self.fid
        self.field_instr = b"\x7e" + struct.pack("<I", self.field_token)

        self.start: int | None = None
        self.state: str = "unknown"
        self.note: str = ""
        self._locate()

    def _locate(self) -> None:
        matches = list(LOADER_PATTERN.finditer(self.il))
        if len(matches) > 1:
            raise PatchError(
                "%d candidate sites in LoaderInit, cannot decide" % len(matches))
        if matches:
            start = matches[0].start()
            token = struct.unpack_from("<I", self.il, start + 1)[0]
            text = self.meta.user_string(token)
            if "关闭下载" not in text and "法律法规" not in text:
                raise PatchError(
                    "unexpected string at candidate site: %r" % text)
            self.start = start
            self.state = "original"
            self.note = text
            return

        post = re.compile(rb"\x00{43}" + re.escape(self.field_instr), re.S)
        hits = list(post.finditer(self.il))
        if len(hits) == 1:
            self.start = hits[0].start()
            self.state = "patched"
            return

        if self.field_instr in self.il and not self._gate_strings():
            self.state = "not_needed"
            return

        raise PatchError(
            "no known structure in LoaderInit (version mismatch?)")

    def _gate_strings(self) -> list[str]:
        out = []
        for m in re.finditer(rb"\x72....", self.il, re.S):
            tok = struct.unpack_from("<I", self.il, m.start() + 1)[0]
            if (tok >> 24) != 0x70:
                continue
            s = self.meta.user_string(tok)
            if "关闭下载" in s or "法律法规" in s:
                out.append(s)
        return out

    @property
    def patch_off(self) -> int:
        assert self.start is not None
        return self.code_off + self.start

    def verify(self) -> None:
        assert self.start is not None
        s, il = self.start, self.il

        def s8(v: int) -> int:
            return v - 256 if v >= 128 else v

        t1 = s + 12 + s8(il[s + 11])
        t2 = s + 19 + s8(il[s + 18])
        for name, t in (("brfalse.s", t1), ("br.s", t2)):
            if not (s <= t < s + NOP_LEN):
                raise PatchError("%s branch target IL_%04X is out of range" % (name, t))

    def build(self) -> bytes:
        assert self.start is not None
        data = bytearray(self.meta.data)
        off = self.patch_off
        data[off:off + NOP_LEN] = b"\x00" * NOP_LEN
        data[off + NOP_LEN:off + PATCH_LEN] = self.field_instr
        return bytes(data)

def describe(data: bytes) -> dict[str, object]:
    pe = PEImage(data)
    meta = Metadata(data, pe)
    info: dict[str, object] = {
        "version_string": meta.version_string,
        "types": meta.rows.get(0x02, 0),
        "methods": meta.rows.get(0x06, 0),
        "fields": meta.rows.get(0x04, 0),
    }
    if meta.rows.get(0x20):
        a = meta.row(0x20, 1)
        info["assembly"] = "%s %d.%d.%d.%d" % (
            meta.string(a["Name"]), a["Major"], a["Minor"],
            a["Build"], a["Revision"])
    info["restrict"] = meta.const_bool("ModSecret", "RestrictMcDownload")
    try:
        t = Target(meta)
        info["loaderinit"] = {
            "rva": meta.row(0x06, t.mid)["RVA"],
            "file_off": t.code_off,
            "size": t.code_size,
            "state": t.state,
            "field_token": "0x%08X" % t.field_token,
            "start": t.start,
        }
    except PatchError as ex:
        info["loaderinit"] = {"error": str(ex)}

    packs = []
    try:
        for tdid in meta.find_typedef("ModModpack"):
            a, b = meta.method_range(tdid)
            for mid in range(a, b):
                if meta.string(meta.row(0x06, mid)["Name"]) != "ModpackInstall":
                    continue
                off, size = meta.method_body(mid)
                il = data[off:off + size]
                msgs = []
                for m in re.finditer(rb"\x72....", il, re.S):
                    tok = struct.unpack_from("<I", il, m.start() + 1)[0]
                    if (tok >> 24) != 0x70:
                        continue
                    s = meta.user_string(tok)
                    if "法律法规" in s or "关闭下载" in s:
                        msgs.append(s)
                packs.append({
                    "sig": meta.blob(meta.row(0x06, mid)["Signature"]).hex(),
                    "rva": meta.row(0x06, mid)["RVA"],
                    "size": size,
                    "gate": bool(msgs),
                })
    except PatchError as ex:
        packs.append({"error": str(ex)})
    info["modpack_install"] = packs
    return info


def fmt_info(info: dict[str, object], path: Path) -> str:
    lines = ["file    : %s" % path]
    if "assembly" in info:
        lines.append("assembly: %s" % info["assembly"])
    lines.append("metadata: %s" % info["version_string"])
    lines.append("tables  : %s types / %s methods / %s fields"
                 % (info["types"], info["methods"], info["fields"]))
    r = info["restrict"]
    lines.append("flag    : ModSecret.RestrictMcDownload = %s"
                 % ("<absent>" if r is None else ("True" if r else "False")))
    li = info["loaderinit"]
    if isinstance(li, dict) and "error" in li:
        lines.append("loader  : %s" % li["error"])
    else:
        state = {"original": "vanilla", "patched": "touched",
                 "not_needed": "clean", "unknown": "unknown"}[li["state"]]
        lines.append("loader  : LoaderInit RVA 0x%X / file 0x%X / %d bytes / %s"
                     % (li["rva"], li["file_off"], li["size"], state))
        if li["start"] is not None:
            lines.append("          site IL_%02X, DlClientListLoader=%s"
                         % (li["start"], li["field_token"]))
        else:
            lines.append("          DlClientListLoader=%s" % li["field_token"])
    for p in info["modpack_install"]:
        if "error" in p:
            lines.append("modpack : <%s>" % p["error"])
        else:
            lines.append("modpack : ModpackInstall %d bytes, hint=%s"
                         % (p["size"], "yes" if p["gate"] else "no"))
    return "\n".join(lines)

DNLIB_VERSION = "4.5.0"
DNLIB_NUPKG = ("https://api.nuget.org/v3-flatcontainer/"
                "dnlib/%s/dnlib.%s.nupkg" % (DNLIB_VERSION, DNLIB_VERSION))
DNLIB_PKG_PAGE = "https://www.nuget.org/packages/dnlib/%s" % DNLIB_VERSION
DNLIB_DLL_IN_ZIP = "lib/net45/dnlib.dll"
CSC_CANDIDATES = (
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
)
NETFRAMEWORK_DL = "https://dotnet.microsoft.com/download/dotnet-framework"


def _download(url: str, what: str, hint: str) -> bytes:
    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DownloadFix.py"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise PatchError("failed to fetch %s: HTTP %d\n  url: %s\n  %s"
                         % (what, e.code, url, hint))
    except urllib.error.URLError as e:
        raise PatchError("failed to fetch %s: %s\n  url: %s\n  %s"
                         % (what, e.reason, url, hint))


def _prepare_tool(cs_url: str) -> Path:
    import io
    import zipfile

    WORK_DIR.mkdir(parents=True, exist_ok=True)

    print("[setup] fetching dnlib %s ..." % DNLIB_VERSION)
    nupkg = _download(
        DNLIB_NUPKG, "dnlib",
        "check access to nuget.org, or download %s manually and extract lib/net45/dnlib.dll."
        % DNLIB_PKG_PAGE)
    dnlib = WORK_DIR / "dnlib.dll"
    try:
        with zipfile.ZipFile(io.BytesIO(nupkg)) as z:
            dnlib.write_bytes(z.read(DNLIB_DLL_IN_ZIP))
    except Exception as e:
        raise PatchError("failed to extract dnlib: %s (manual download: %s)" % (e, DNLIB_PKG_PAGE))

    print("[setup] fetching helper source ...")
    cs = WORK_DIR / "PatchModpack.cs"
    cs.write_bytes(_download(
        cs_url, "PatchModpack.cs",
        "check the source URL, or pass another one with --cs-url."))

    csc = next((c for c in CSC_CANDIDATES if Path(c).is_file()), None)
    if csc is None:
        raise PatchError(
            "C# compiler (csc.exe) not found.\n"
            "  Install .NET Framework 4.x: %s" % NETFRAMEWORK_DL)
    exe = WORK_DIR / "PatchModpack.exe"
    print("[setup] building helper ...")
    r = subprocess.run(
        [csc, "/nologo", "/codepage:65001",
         "/r:" + str(dnlib), "/out:" + str(exe), str(cs)],
        capture_output=True, text=True, timeout=120, cwd=str(WORK_DIR))
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        raise PatchError("build failed (%s)" % csc)
    print("  helper ready")
    return exe


def _cleanup_workdir() -> None:
    shutil.rmtree(WORK_DIR, ignore_errors=True)


def run_modpack(src: Path, out: Path, cs_url: str) -> None:
    print("[1/2] applying modpack module ...")
    exe = _prepare_tool(cs_url)
    r = subprocess.run([str(exe), str(src), str(out)],
                       capture_output=True, text=True, timeout=600)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        raise PatchError("helper exited with an error")
    print("  -> %s" % out)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="DownloadFix",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("exe", nargs="?",
                   help="input exe (default: Plain Craft Launcher 2.exe next to this script)")
    p.add_argument("-o", "--output", help="output file (default: <name> (Patched).exe)")
    p.add_argument("--force", action="store_true", help="overwrite existing output")
    p.add_argument("--inspect", action="store_true", help="print analysis only, no changes")
    p.add_argument("--in-place", action="store_true",
                   help="write back into the original file (a .bak backup is made)")
    p.add_argument("--cs-url", metavar="URL", default=CS_URL,
                   help="URL of the helper source PatchModpack.cs (default: CS_URL in script)")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("=" * 64)
    print("DownloadFix - an unofficial third-party tool.")
    print("PCL is developed by LTCatt: https://github.com/Meloong-Git/PCL")
    print("This tool ships no part of PCL; it only adjusts your local copy.")
    print("Results are for personal use only. Check your local laws")
    print("and the PCL license before proceeding.")
    print("Do not distribute without authorization!")
    print("=" * 64)

    args = parse_args(argv)
    src = Path(args.exe) if args.exe else DEFAULT_EXE
    if not src.is_file():
        print("[x] file not found: %s" % src)
        return 1
    data = src.read_bytes()

    if args.inspect:
        try:
            print(fmt_info(describe(data), src))
        except PatchError as ex:
            print("[x] %s" % ex)
        return 0

    stage = WORK_DIR / "modpack_stage.tmp.exe"

    try:
        run_modpack(src, stage, args.cs_url)

        print("[2/2] Download Fix")
        mid_data = stage.read_bytes()
        target = Target(Metadata(mid_data, PEImage(mid_data)))
        label = {"original": "pending",
                 "patched": "already done",
                 "not_needed": "not required"}[target.state]
        print("  state : %s" % label)
        if target.state == "original":
            target.verify()
            patched = target.build()
        else:
            patched = mid_data
    except PatchError as ex:
        print("[x] %s" % ex)
        return 1
    finally:
        _cleanup_workdir()

    check = Target(Metadata(patched, PEImage(patched)))
    if check.state != "patched":
        print("[x] internal error: verification failed (state=%s)" % check.state)
        return 1

    if args.in_place:
        backup = src.with_suffix(src.suffix + ".bak")
        if backup.exists():
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = src.with_suffix(src.suffix + ".%s.bak" % stamp)
        shutil.copy2(src, backup)
        print("backup : %s" % backup)
        dst = src
    else:
        dst = Path(args.output) if args.output else src.with_name(
            "%s (Patched)%s" % (src.stem, src.suffix))
        if dst.exists() and not args.force:
            if dst.read_bytes() == patched:
                print("[=] output is identical, skipped: %s" % dst)
                return 0
            print("[x] output exists (use --force to overwrite): %s" % dst)
            return 1

    dst.write_bytes(patched)
    print("output : %s" % dst)
    print("SHA256: %s" % sha256(patched))
    print()
    print("[√] All done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))