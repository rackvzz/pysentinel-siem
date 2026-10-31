# Third-Party Notices

pysentinel-siem itself is released under the [MIT License](LICENSE). It uses, and the Windows `.exe` release bundles, the components below. Each remains under its own license.

## Python dependencies

| Component | License | Used for |
|---|---|---|
| [pywin32](https://github.com/mhammond/pywin32) | PSF-2.0 | Windows Event Log API, notifications |
| [Flask](https://github.com/pallets/flask) | BSD-3-Clause | Browser dashboard |
| [Werkzeug](https://github.com/pallets/werkzeug), [Jinja2](https://github.com/pallets/jinja), [MarkupSafe](https://github.com/pallets/markupsafe), [itsdangerous](https://github.com/pallets/itsdangerous), [click](https://github.com/pallets/click) | BSD-3-Clause | Flask dependencies |
| [blinker](https://github.com/pallets-eco/blinker) | MIT | Flask dependency |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT | Config files |
| [defusedxml](https://github.com/tiran/defusedxml) | PSF-2.0 | Hardened XML parsing |

## Bundled in the `.exe` release

| Component | License |
|---|---|
| CPython runtime | PSF-2.0 |
| Tcl/Tk (Tkinter GUI toolkit) | Tcl/Tk license (BSD-style) |
| [PyInstaller](https://pyinstaller.org/) bootloader | GPL-2.0 with the PyInstaller bootloader exception, which permits distributing bundled apps under any license |

## Configuration and data

**Sysmon configuration** (`sysmon/sysmonconfig-export.xml`)
Based on [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), licensed under [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/). The original attribution header is kept in the file. This project's modification adds a ProcessAccess rule scoped to `lsass.exe`.

**Sysmon** (Microsoft Sysinternals)
Not included in this repository or its releases. You download it from Microsoft and accept the Sysinternals license yourself. `sysmon/*.exe` is git-ignored on purpose.

**abuse.ch ThreatFox data** (optional, off by default)
Indicators are downloaded at runtime and are not redistributed with this project. ThreatFox's terms describe the datasets as CC0 and say they are provided as-is, with no warranty and no liability for false positives. The API is free under fair-use principles. abuse.ch states that commercial or for-profit use may require a paid subscription. See the [ThreatFox FAQ and terms](https://threatfox.abuse.ch/faq/) and the [abuse.ch terms of use](https://abuse.ch/terms-of-use/).
