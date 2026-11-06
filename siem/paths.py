"""Where the app keeps its data, and making sure that place is safe.

The packaged app always runs as Administrator (it reads the Security log).
Anything it reads or writes while elevated has to live somewhere a normal,
non-admin program can't touch. Otherwise malware without admin rights could:

  - edit config.yaml / user_settings.yaml and have the elevated app act on it
    (e.g. point db_path at a system file and let icacls hand it over)
  - swap siem.db or the log file for a link to a system file
  - read the collected Security-log data, which Windows itself only shows
    to admins

So the packaged exe keeps everything in %ProgramData%\\pysentinel-siem,
owned by Administrators and readable/writable only by Administrators and
SYSTEM. Running from source (python desktop_app.py / run_collector.py) keeps
the old behavior -- files next to the code -- since that's a dev setup.
"""

import logging
import os
import re
import shutil
import subprocess
import sys
import time

logger = logging.getLogger("siem.paths")

APP_FOLDER = "pysentinel-siem"
SYSTEM_SID = "S-1-5-18"
ADMINS_SID = "S-1-5-32-544"
TRUSTED_OWNERS = (SYSTEM_SID, ADMINS_SID)

ICACLS_EXE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")

# files the app creates; copied over once from the old next-to-the-exe location
MIGRATE_FILES = ("config.yaml", "user_settings.yaml", "secrets.yaml", "siem.db")

_SAFE_DB_NAME = re.compile(r"^[A-Za-z0-9_.-]+\.db$")


class UnsafeDataDirError(RuntimeError):
    pass


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def exe_dir() -> str:
    if is_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def data_dir() -> str:
    if is_frozen():
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(base, APP_FOLDER)
    return exe_dir()


def resolve_db_path(configured: str | None, directory: str) -> str:
    """db_path from config is only allowed to be a plain file name inside the
    data directory. Absolute paths and anything with a folder in it are
    ignored, so an edited config can't aim the elevated app at another file."""
    name = configured or "siem.db"
    if not _SAFE_DB_NAME.match(name):
        logger.warning("Ignoring db_path %r from config -- only a plain file name like siem.db is allowed.", name)
        name = "siem.db"
    return os.path.join(directory, name)


def is_reparse_point(path: str) -> bool:
    """True for symlinks and junctions (on Windows, both are reparse points)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if os.path.islink(path):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def owner_sid(path: str) -> str | None:
    try:
        import win32security
    except ImportError:
        return None
    sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
    return win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())


def _icacls(*args: str) -> None:
    result = subprocess.run([ICACLS_EXE, *args], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise UnsafeDataDirError(f"icacls {' '.join(args)} failed: {(result.stdout or result.stderr).strip()}")


def secure_directory(path: str) -> None:
    """Make `path` an Administrators-owned folder that only Administrators
    and SYSTEM can use. A folder that already exists but wasn't created by
    an admin (anyone can make folders in ProgramData) is moved aside instead
    of trusted, since whoever made it could have planted files in it."""
    if is_reparse_point(path):
        raise UnsafeDataDirError(f"{path} is a symlink or junction -- refusing to use it.")

    if os.path.isdir(path):
        owner = owner_sid(path)
        if owner is not None and owner not in TRUSTED_OWNERS:
            quarantine = f"{path}.untrusted-{int(time.time())}"
            logger.warning("%s is owned by %s, not Administrators/SYSTEM -- moving it to %s and starting fresh.",
                           path, owner, quarantine)
            os.rename(path, quarantine)

    os.makedirs(path, exist_ok=True)
    if is_reparse_point(path):
        raise UnsafeDataDirError(f"{path} turned into a symlink or junction -- refusing to use it.")

    _icacls(path, "/setowner", f"*{ADMINS_SID}")
    _icacls(path, "/inheritance:r", "/grant:r", f"*{SYSTEM_SID}:(OI)(CI)F", f"*{ADMINS_SID}:(OI)(CI)F")


def migrate_old_files(old_dir: str, new_dir: str) -> list[str]:
    """One-time copy of data from the old next-to-the-exe location. Only
    copies regular files (no links), and never overwrites anything."""
    moved = []
    if os.path.normcase(os.path.abspath(old_dir)) == os.path.normcase(os.path.abspath(new_dir)):
        return moved
    for name in MIGRATE_FILES:
        src, dst = os.path.join(old_dir, name), os.path.join(new_dir, name)
        if os.path.exists(dst) or not os.path.isfile(src) or is_reparse_point(src):
            continue
        shutil.copyfile(src, dst, follow_symlinks=False)
        moved.append(name)
    if moved:
        logger.info("Moved %s from %s to %s. The old copies can be deleted.", ", ".join(moved), old_dir, new_dir)
    return moved


def prepare_data_dir() -> str:
    """Call once at startup, before anything is read or written. Returns the
    directory to use for config, settings, secrets, the database, and logs."""
    directory = data_dir()
    if is_frozen():
        secure_directory(directory)
        migrate_old_files(exe_dir(), directory)
    return directory
