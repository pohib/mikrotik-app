# MikroTik VPN Manager — v1.1.0

## Launch (Windows 10/11)
1. Extract the complete folder from the ZIP.
2. Install Python 3.10 or newer from https://www.python.org/downloads/ (enable Python Launcher or PATH).
3. Double-click `start.bat`.
4. The launcher creates `.venv`, installs `requirements.txt`, checks imports, then starts `app.py`. The import check deliberately avoids quoted string literals for compatibility with Windows PowerShell 5.1 native argument passing.

The launcher uses PowerShell to avoid Windows CMD parsing/encoding issues. It keeps the console open until a key is pressed and writes startup output to `startup.log`.

If startup fails, send `startup.log` and the error shown in the console.

## Interface
- Dark graphite interface with a compact navigation sidebar, clearer dashboard hierarchy, metric cards and high-contrast controls.
- Separate searchable operation log.

## Notes
- The application uses SSH and does not change router settings merely by connecting.
- Review the command preview before applying configuration changes.
- Keep a separate backup of the router configuration before applying changes.


## v1.1.0
- Refreshed dashboard and global visual system: graphite palette, blue/teal accents, clearer hierarchy, improved spacing, controls and navigation.
- Fixed the PowerShell 5.1 import check: no quoted string literals are passed through `python -c`.
- Python candidate discovery no longer relies on quoted string literals inside the native command line.
