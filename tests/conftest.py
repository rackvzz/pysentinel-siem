"""Shared test setup.

The real app only runs on Windows, but the tests are meant to run anywhere
(Linux CI, a reviewer's Mac). pywin32 doesn't install off Windows, so when it's
missing we put stand-in modules in sys.modules before any siem code imports
them. Tests that care about these APIs already monkeypatch the functions they
call, so the stand-ins only need to exist.
"""

import sys
import types
from unittest import mock


class _StubModule(types.ModuleType):
    # any attribute read gets a MagicMock that's saved on the module, so
    # monkeypatch can swap it and put it back like a normal attribute
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        value = mock.MagicMock(name=f"{self.__name__}.{name}")
        setattr(self, name, value)
        return value


try:
    import win32api  # noqa: F401
except ImportError:
    pywintypes = types.ModuleType("pywintypes")

    class _Win32Error(Exception):
        def __init__(self, winerror=0, funcname="", strerror=""):
            super().__init__(winerror, funcname, strerror)
            self.winerror = winerror

    pywintypes.error = _Win32Error
    sys.modules["pywintypes"] = pywintypes

    for name in ("win32api", "win32con", "win32gui", "win32evtlog"):
        sys.modules[name] = _StubModule(name)
