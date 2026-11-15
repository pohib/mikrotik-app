# MikroTik VPN Manager — v1.2.0

## v1.4.0 — Deep diagnostics

- Reworked the full diagnostic into a single layered, read-only run.
- Checks RouterOS identity/resources/clock, WAN interface and main default route, WAN reachability, DNS/DoH configuration and actual DNS resolution, DHCP network and leases, WireGuard interface/peer/handshake, VPN route and an interface-bound ping probe, managed Mangle/NAT counters, DNS redirect/FWD entries, FastTrack, IPv6 default route, and recent network warnings/errors.
- Adds local Windows client DNS resolution and TCP/443 checks to separate client-side failures from router-side failures. These are clearly labeled because Windows may use a different resolver.
- Shows likely fault area, severity, evidence collected during the same run, and next action. A failed/unsupported command is marked inconclusive rather than automatically treated as a network outage.
- Full diagnostics no longer add temporary routing rules or alter router configuration.
- Added copy and UTF-8 TXT export of the complete report, including raw command evidence.

## v1.3.0 — UX and usability

- Startup opens the dashboard without forcing an SSH login dialog; connect when ready.
- Reduced minimum window size and refined spacing for more laptop-friendly layouts.
- Added Ctrl+1…Ctrl+8 navigation shortcuts and Ctrl+L for the operation log.
- Added visible indeterminate progress while a router operation is running and clearer busy feedback.
- Added an explanatory empty state for the routing-target list.
- Improved focus, table selection and progress styling.
- Existing staged-change confirmation and router safety checks are retained.



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

## v1.2.0 — DNS / DoH and diagnostics
- Added configurable DNS-over-HTTPS controls (endpoint, enable/disable, TLS certificate verification) in Settings. Changes are staged and require explicit confirmation before being sent to the router.
- The repair workflow now preserves the selected DoH policy, keeps bootstrap DNS servers configured, checks managed NAT/Mangle prerequisites, and flushes DNS cache after changes.
- Added a read-only DoH inspection action that displays RouterOS DNS configuration and DNS error log entries.
- Added per-domain diagnostics: RouterOS DNS resolution, DNS cache, dynamic address-list entries, managed FWD record, Mangle counters, WireGuard peer counters, and the VPN routing table.
- Diagnostics explicitly treat Mangle and WireGuard counters as router-wide counters, not per-domain proof.
- DoH is configured with TLS certificate verification enabled; the app refuses to apply an enabled DoH profile with certificate verification disabled.

### Important operational notes
- RouterOS DoH does not automatically fall back to plain DNS when the DoH endpoint fails. The regular DNS servers remain configured for resolving the DoH endpoint hostname.
- DNS static FWD records may have forwarding behavior separate from the global DoH resolver. Verify the behavior of any FWD entries before treating all upstream DNS traffic as encrypted.
- The app has not been executed against the user's router as part of this repository update. Review the command preview and create a router backup before applying changes.
