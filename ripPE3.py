#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import hashlib
import os
import re
import sqlite3
import sys
import time
from typing import Optional, List
import pefile


_SANIT = re.compile(r"[^A-Za-z0-9_.-]+")
_RT = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
}

def _sane(s: str) -> str:
    if not s:
        s = "unnamed"
    return _SANIT.sub("_", s)[:80]

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

class RipPE:
    def __init__(
        self,
        file_to_rip: str,
        dump_mode: bool = False,
        into_db: bool = False,
        session: Optional[str] = None,
        hash_mode: str = "sha256",
        ssdeep_it: bool = False,
    ) -> None:
        self.path = os.path.abspath(file_to_rip)
        self.dump = dump_mode
        self.into_db = into_db
        self.session = session or "default"
        self.hash_mode = hash_mode.lower()
        self.use_ssdeep = ssdeep_it
        self.ssdeep = None
        if self.use_ssdeep:
            try:
                import ssdeep  # type: ignore
                self.ssdeep = ssdeep
            except Exception:
                self.use_ssdeep = False
        self.pe: Optional[pefile.PE] = None
        self.dbcon: Optional[sqlite3.Connection] = None
        try:
            self.pe = pefile.PE(self.path, fast_load=False)
        except Exception:
            print("FAIL,FAIL,FAIL")
            sys.exit(1)
        self.hashes = self._compute_hashes(self.path, self.hash_mode)
        self.file_sha256 = self.hashes["sha256"]
        if self.into_db:
            self._ensure_db()

    def _compute_hashes(self, path: str, algo: str) -> dict:
        BUFSZ = 1024 * 1024
        algos = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}
        if algo not in algos:
            algo = "sha256"
        hsel = algos[algo]()
        h_md5 = hashlib.md5()
        h_sha1 = hashlib.sha1()
        h_sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(BUFSZ)
                if not chunk:
                    break
                hsel.update(chunk)
                h_md5.update(chunk)
                h_sha1.update(chunk)
                h_sha256.update(chunk)
        out = {
            "selected": hsel.hexdigest(),
            "md5": h_md5.hexdigest(),
            "sha1": h_sha1.hexdigest(),
            "sha256": h_sha256.hexdigest(),
        }
        if self.use_ssdeep and self.ssdeep:
            try:
                out["ssdeep"] = self.ssdeep.hash_from_file(path)
            except Exception:
                out["ssdeep"] = ""
        return out

    def _ensure_db(self) -> None:
        os.makedirs("./dbripPE", exist_ok=True)
        self.dbcon = sqlite3.connect("./dbripPE/ripPE.db")
        self.dbcon.execute(
            """CREATE TABLE IF NOT EXISTS ripPE (
                session TEXT NOT NULL,
                date INTEGER NOT NULL,
                file TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT
            )"""
        )
        self.dbcon.commit()

    def _emit(self, label: str, category: str, value: str) -> None:
        line = f"{os.path.basename(self.path)},{self.hashes['md5']},{label},{category},{value}"
        print(line)
        if self.into_db and self.dbcon:
            self.dbcon.execute(
                "INSERT INTO ripPE(session,date,file,key,value) VALUES(?,?,?,?,?)",
                (self.session, int(time.time()), self.path, f"{label}:{category}", value),
            )

    def list_standard(self) -> None:
        assert self.pe
        pe = self.pe
        self._emit("HEADER", "Machine", hex(pe.FILE_HEADER.Machine))
        self._emit("HEADER", "NumberOfSections", str(pe.FILE_HEADER.NumberOfSections))
        self._emit("HEADER", "TimeDateStamp", str(pe.FILE_HEADER.TimeDateStamp))
        self._emit("HEADER", "Characteristics", hex(pe.FILE_HEADER.Characteristics))
        self._emit("HEADER", "ImageBase", hex(pe.OPTIONAL_HEADER.ImageBase))
        self._emit("HEADER", "AddressOfEntryPoint", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        self._emit("HEADER", "Subsystem", str(pe.OPTIONAL_HEADER.Subsystem))
        self._emit("HEADER", "DllCharacteristics", hex(pe.OPTIONAL_HEADER.DllCharacteristics))
        self._emit("HEADER", "SizeOfImage", str(pe.OPTIONAL_HEADER.SizeOfImage))

    def dump_iat(self) -> None:
        assert self.pe
        pe = self.pe
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except Exception:
            pass
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return
        lines = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dllname = entry.dll.decode(errors="ignore") if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
            for imp in entry.imports:
                name = ""
                if imp.name:
                    name = imp.name.decode(errors="ignore") if isinstance(imp.name, (bytes, bytearray)) else str(imp.name)
                elif imp.ordinal:
                    name = f"ordinal_{imp.ordinal}"
                lines.append(f"{dllname},{hex(imp.address)},{name}")
                self._emit("IAT", dllname, f"{hex(imp.address)}:{name}")
        if self.dump and lines:
            blob = ("\n".join(lines) + "\n").encode("utf-8", "ignore")
            fname = f"ripPE-IAT-{self.file_sha256}-{_sha256_bytes(blob)}.iat"
            with open(fname, "wb") as wf:
                wf.write(blob)
            self._emit("DUMP_IAT", "FILE", fname)

    def list_imports(self) -> None:
        assert self.pe
        pe = self.pe
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except Exception:
            pass
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return
        dlls = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dllname = entry.dll.decode(errors="ignore") if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
            dlls.append(dllname)
            self._emit("IMPORTS", "DLL", dllname)
        if self.dump and dlls:
            blob = ("\n".join(dlls) + "\n").encode("utf-8", "ignore")
            fname = f"ripPE-IMPORT-{self.file_sha256}-{_sha256_bytes(blob)}.import"
            with open(fname, "wb") as wf:
                wf.write(blob)
            self._emit("DUMP_IMPORT", "FILE", fname)

    def dump_import(self) -> None:
        self.dump_iat()

    def list_exports(self) -> None:
        assert self.pe
        pe = self.pe
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        except Exception:
            pass
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode(errors="ignore") if isinstance(exp.name, (bytes, bytearray)) else str(exp.name)
            self._emit("EXPORTS", "Symbol", f"{name or ''}:{hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)}")

    def get_virtual_section_info(self) -> None:
        assert self.pe
        pe = self.pe
        for sec in pe.sections:
            sname = sec.Name.rstrip(b"\x00").decode(errors="ignore")
            self._emit("SECTIONS", sname, f"VA={hex(sec.VirtualAddress)} VSZ={hex(sec.Misc_VirtualSize)} RSZ={hex(sec.SizeOfRawData)}")

    def dump_sections(self) -> None:
        assert self.pe
        base_sha = self.file_sha256
        for sec in self.pe.sections:
            raw = b""
            try:
                raw = sec.get_data()
            except Exception:
                try:
                    with open(self.path, "rb") as f:
                        f.seek(sec.PointerToRawData)
                        raw = f.read(sec.SizeOfRawData)
                except Exception:
                    raw = b""
            sname = sec.Name.rstrip(b"\x00").decode(errors="ignore") or "unnamed"
            sname = sname.lstrip(".").lower()
            ext = sname if sname in ("text","data","rdata","rsrc","reloc","pdata") else "sec"
            fname = f"ripPE-SECTION-{base_sha}-{_sane(sname)}-{_sha256_bytes(raw)}.{ext}"
            try:
                with open(fname, "wb") as wf:
                    wf.write(raw or b"")
                self._emit("DUMP_SECTION", sname, fname)
            except Exception:
                continue

    def get_debug(self) -> None:
        assert self.pe
        pe = self.pe
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
        except Exception:
            pass
        if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            return
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            self._emit("DEBUG", "Type", str(dbg.struct.Type))
            self._emit("DEBUG", "SizeOfData", str(dbg.struct.SizeOfData))
            self._emit("DEBUG", "AddressOfRawData", hex(dbg.struct.AddressOfRawData))
            if self.dump and dbg.struct.SizeOfData and dbg.struct.AddressOfRawData:
                try:
                    with open(self.path, "rb") as f:
                        f.seek(dbg.struct.AddressOfRawData)
                        blob = f.read(dbg.struct.SizeOfData)
                    fname = f"ripPE-DEBUG-{self.file_sha256}-{_sha256_bytes(blob)}.debug"
                    with open(fname, "wb") as wf:
                        wf.write(blob)
                    self._emit("DUMP_DEBUG", "FILE", fname)
                except Exception:
                    pass

    def get_resource_info(self) -> None:
        assert self.pe
        pe = self.pe
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        except Exception:
            pass
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return
        def _name_of(entry) -> str:
            try:
                if getattr(entry, "name", None):
                    raw = entry.name
                    if hasattr(raw, "string"):
                        return raw.string.decode(errors="ignore")
                    return str(raw)
                if getattr(entry, "id", None) in _RT:
                    return "RT_" + _RT[entry.id]
                return str(entry.id)
            except Exception:
                return "UNK"
        def _walk(res_dir, path=""):
            for entry in getattr(res_dir, "entries", []):
                name = _name_of(entry)
                next_path = f"{path}/{name}" if path else name
                if hasattr(entry, "directory") and entry.directory:
                    _walk(entry.directory, next_path)
                if hasattr(entry, "data") and entry.data:
                    data_obj = entry.data
                    items = []
                    if hasattr(data_obj, "structs") and data_obj.structs:
                        items = data_obj.structs
                    elif hasattr(data_obj, "struct"):
                        items = [data_obj.struct]
                    for d in items:
                        try:
                            rva = getattr(d, "OffsetToData", None)
                            sz = getattr(d, "Size", None)
                            if rva is None or sz is None:
                                continue
                            blob = pe.get_data(rva, sz) or b""
                            type_ident = next_path.split("/", 1)[0]
                            self._emit("RESOURCES", path or "ROOT", f"RVA={hex(rva)} SZ={sz}")
                            if self.dump:
                                ident = _sane(type_ident)
                                fname = f"ripPE-RESOURCE-{self.file_sha256}-{ident}-{_sha256_bytes(blob)}.rsrc"
                                with open(fname, "wb") as wf:
                                    wf.write(blob)
                                self._emit("DUMP_RESOURCE", ident, fname)
                        except Exception:
                            continue
        _walk(pe.DIRECTORY_ENTRY_RESOURCE)

    def dump_cert(self) -> None:
        assert self.pe
        pe = self.pe
        try:
            secdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            if secdir.VirtualAddress and secdir.Size:
                with open(self.path, "rb") as f:
                    f.seek(secdir.VirtualAddress)
                    cert_blob = f.read(secdir.Size)
                if self.dump and cert_blob:
                    fname = f"ripPE-CERT-{self.file_sha256}-{_sha256_bytes(cert_blob)}.crt"
                    with open(fname, "wb") as wf:
                        wf.write(cert_blob)
                    self._emit("DUMP_CERT", "FILE", fname)
                else:
                    self._emit("DUMP_CERT", "SIZE", str(len(cert_blob)))
        except Exception:
            pass

    def run_all(self) -> None:
        self.list_standard()
        self.dump_iat()
        self.list_imports()
        self.dump_import()
        self.list_exports()
        self.get_virtual_section_info()
        if self.dump:
            self.dump_sections()
        self.get_debug()
        self.get_resource_info()
        self.dump_cert()

    def db_close(self) -> None:
        if self.dbcon:
            self.dbcon.commit()
            self.dbcon.close()
            self.dbcon = None

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="ripPE_py3_v4",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Extrae metadatos de binarios PE.",
    )
    p.add_argument("--file", "-f", required=True, help="Ruta al PE")
    p.add_argument("--section", "-s", dest="ripSection", choices=[
        "all","header","iat","imports","exports","debug","sections","resources","dump_cert"
    ], default="all", help="Sección a procesar")
    p.add_argument("--dump", action="store_true", help="Volcar artefactos a ficheros")
    p.add_argument("--into-db", action="store_true", help="Guardar salida en SQLite ./dbripPE/ripPE.db")
    p.add_argument("--session", default=None, help="Nombre de sesión para DB")
    p.add_argument("--hash_mode", choices=["md5","sha1","sha256"], default="sha256", help="Hash principal a mostrar")
    p.add_argument("--ssdeep", action="store_true", help="Calcular ssdeep si está disponible")
    return p.parse_args(argv)

def main(argv: List[str]) -> None:
    args = parse_args(argv)
    pe = RipPE(
        args.file,
        dump_mode=args.dump,
        into_db=args.into_db,
        session=args.session,
        hash_mode=args.hash_mode,
        ssdeep_it=args.ssdeep,
    )
    sec = args.ripSection.upper()
    if sec == "ALL":
        pe.run_all()
    elif sec == "HEADER":
        pe.list_standard()
    elif sec == "IAT":
        pe.dump_iat()
    elif sec == "IMPORTS":
        pe.list_imports()
    elif sec == "EXPORTS":
        pe.list_exports()
    elif sec == "DEBUG":
        pe.get_debug()
    elif sec == "SECTIONS":
        pe.get_virtual_section_info()
        if args.dump:
            pe.dump_sections()
    elif sec == "RESOURCES":
        pe.get_resource_info()
    elif sec == "DUMP_CERT":
        pe.dump_cert()
    else:
        print("Something bad happened...")
    if args.into_db:
        pe.db_close()

if __name__ == "__main__":
    main(sys.argv[1:])
