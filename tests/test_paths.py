import os
import sys

import pytest

from siem import file_security, paths

# ---- db_path can't escape the data folder ----

@pytest.mark.parametrize("configured", [
    r"C:\Windows\System32\evil.dll",
    "/etc/passwd",
    r"..\..\Windows\System32\x.db",
    "../x.db",
    r"sub\siem.db",
    "siem.db:stream",
    "",
    None,
])
def test_db_path_from_config_is_forced_into_the_data_folder(tmp_path, configured):
    result = paths.resolve_db_path(configured, str(tmp_path))
    assert result == os.path.join(str(tmp_path), "siem.db")


def test_plain_db_file_name_is_allowed(tmp_path):
    assert paths.resolve_db_path("events-2026.db", str(tmp_path)) == os.path.join(str(tmp_path), "events-2026.db")


# ---- securing the data folder ----

@pytest.fixture
def icacls_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(paths, "_icacls", lambda *args: calls.append(args))
    return calls


def test_secure_directory_sets_admin_owner_and_admin_only_acl(tmp_path, icacls_calls, monkeypatch):
    monkeypatch.setattr(paths, "owner_sid", lambda p: paths.ADMINS_SID)
    target = str(tmp_path / "pysentinel-siem")
    paths.secure_directory(target)
    assert os.path.isdir(target)
    assert icacls_calls[0] == (target, "/setowner", f"*{paths.ADMINS_SID}")
    assert icacls_calls[1] == (
        target, "/inheritance:r", "/grant:r",
        f"*{paths.SYSTEM_SID}:(OI)(CI)F", f"*{paths.ADMINS_SID}:(OI)(CI)F",
    )


def test_folder_pre_created_by_a_normal_user_is_moved_aside(tmp_path, icacls_calls, monkeypatch):
    # anyone can create folders in ProgramData -- a squatted folder could
    # hold a planted config.yaml, so it must not be trusted
    target = tmp_path / "pysentinel-siem"
    target.mkdir()
    (target / "config.yaml").write_text("db_path: C:/Windows/System32/evil.dll\n")
    monkeypatch.setattr(paths, "owner_sid", lambda p: "S-1-5-21-1111-2222-3333-1001")

    paths.secure_directory(str(target))

    assert not (target / "config.yaml").exists()
    quarantined = [p for p in tmp_path.iterdir() if p.name.startswith("pysentinel-siem.untrusted-")]
    assert len(quarantined) == 1 and (quarantined[0] / "config.yaml").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs extra rights on Windows")
def test_symlinked_data_folder_is_refused(tmp_path, icacls_calls):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "pysentinel-siem"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(paths.UnsafeDataDirError):
        paths.secure_directory(str(link))
    assert icacls_calls == []


def test_icacls_failure_stops_startup(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "owner_sid", lambda p: None)

    class Result:
        returncode = 5
        stdout = "Access is denied."
        stderr = ""

    monkeypatch.setattr(paths.subprocess, "run", lambda *a, **k: Result())
    with pytest.raises(paths.UnsafeDataDirError):
        paths.secure_directory(str(tmp_path / "d"))


def test_source_checkout_uses_the_repo_folder(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert paths.data_dir() == paths.exe_dir()


def test_packaged_exe_uses_programdata(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("ProgramData", str(tmp_path))
    assert paths.data_dir() == os.path.join(str(tmp_path), "pysentinel-siem")


# ---- migrating from the old next-to-the-exe location ----

def test_migration_copies_regular_files_once(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "siem.db").write_bytes(b"data")
    (old / "user_settings.yaml").write_text("ui: {theme: dark}\n")
    (new / "user_settings.yaml").write_text("ui: {theme: light}\n")

    moved = paths.migrate_old_files(str(old), str(new))

    assert moved == ["siem.db"]
    assert (new / "siem.db").read_bytes() == b"data"
    assert "light" in (new / "user_settings.yaml").read_text()  # never overwritten


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs extra rights on Windows")
def test_migration_skips_links(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    new.mkdir()
    secret = tmp_path / "protected.txt"
    secret.write_text("not yours")
    (old / "secrets.yaml").symlink_to(secret)
    assert paths.migrate_old_files(str(old), str(new)) == []


# ---- icacls is never pointed at a link ----

@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs extra rights on Windows")
def test_restrict_refuses_symlink(tmp_path, monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    target = tmp_path / "system_file"
    target.write_text("x")
    link = tmp_path / "siem.db"
    link.symlink_to(target)
    ran = []
    monkeypatch.setattr(file_security.subprocess, "run", lambda *a, **k: ran.append(a))
    assert file_security.restrict_to_current_user(str(link)) is False
    assert ran == []


def test_restrict_refuses_hard_link(tmp_path, monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    target = tmp_path / "system_file"
    target.write_text("x")
    link = tmp_path / "siem.db"
    os.link(target, link)
    ran = []
    monkeypatch.setattr(file_security.subprocess, "run", lambda *a, **k: ran.append(a))
    assert file_security.restrict_to_current_user(str(link)) is False
    assert ran == []


def test_packaged_exe_leaves_acls_to_the_data_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    f = tmp_path / "siem.db"
    f.write_text("x")
    ran = []
    monkeypatch.setattr(file_security.subprocess, "run", lambda *a, **k: ran.append(a))
    assert file_security.restrict_to_current_user(str(f)) is True
    assert ran == []
