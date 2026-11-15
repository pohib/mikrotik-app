# MikroTik VPN Manager — v1.6.0

## v1.6.0 — Dialog UI and routing diagnostics

### UI
- All application-owned secondary windows use frameless dark styling with a custom draggable title bar and close control: dependency discovery, preview, and apply queue.
- Message boxes use the same visual theme instead of native Windows message windows.
- File open/save/folder pickers use Qt dialogs with the native Windows dialog disabled and the application theme applied.
- Explicit dialog background styling prevents the white surface previously visible in the apply-changes window.
- SSH login already had a custom frameless interface and remains unchanged.

### Stage 1 diagnostics
- Expanded IPv6 inspection: global settings, addresses, active/default routes, IPv6 firewall filter, and Neighbor Discovery / Router Advertisement configuration.
- Reports a possible IPv6 VPN bypass when a global IPv6 address and default route are present; it does not automatically disable IPv6 or alter firewall rules.
- FastTrack analysis lists active FastTrack rules and counters; client-specific domain checks inspect conntrack entries for the selected LAN client and resolved service IPs, including an explicit warning when fasttrack=yes is present.
- Domain route lookup uses addresses extracted from RouterOS resolve output, DNS cache, and managed dynamic address-list entries, then inspects active routes in both main and the configured VPN table.
- Client checks include conntrack, FastTrack counters, Mangle counters, and IPv6 neighbor evidence.
- All added diagnostics are read-only. A conntrack snapshot only proves that a matching connection record was present at the moment of inspection; generate traffic from the client during the check for useful evidence. It does not prove that every packet of a flow followed the expected path.



## v1.5.0 — Destination-aware routing diagnostics

- Full diagnostics now resolve the selected domain and inspect active IPv4 routes matching each returned address in both the main and configured VPN routing tables (up to five returned addresses).
- The separate per-domain diagnostic performs the same main/VPN route-table inspection after DNS resolution.
- Route evidence includes the exact RouterOS command and output, making it possible to compare the selected address against the active route and next-hop in each table.
- Added explicit read-only inspection of global IPv6 settings and IPv6 default routes.
- Added detailed Mangle and firewall-filter counters to the diagnostic evidence, including FastTrack counters.
- The report distinguishes route-table evidence from packet-level proof: a route in the VPN table does not alone prove that a particular LAN client's packets matched Mangle or avoided FastTrack. Check the managed address-list and counters alongside the route result.
- All new checks are read-only. They do not add, remove, enable, disable, or reorder router configuration.



## v1.4.0 — Deep diagnostics

- Reworked the full diagnostic into a single layered, read-only run.
- Checks RouterOS identity/resources/clock, WAN interface and main default route, WAN reachability, DNS/DoH configuration and actual DNS resolution, DHCP network and leases, WireGuard interface/peer/handshake, VPN route and an interface-bound ping probe, managed Mangle/NAT counters, DNS redirect/FWD entries, FastTrack, IPv6 default route, and recent network warnings/errors.
- Adds local Windows client DNS resolution and TCP/443 checks to separate client-side failures from router-side failures. These are clearly labeled because Windows may use a different resolver.
- Shows likely fault area, severity, evidence collected during the same run, and next action. A failed/unsupported command is marked inconclusive rather than automatically treated as a network outage.
- Full diagnostics no longer add temporary routing rules or alter router configuration.
- Added copy and UTF-8 TXT export of the complete report, including raw command evidence.
- If a domain is entered in the diagnostics field, the full run also checks its DNS resolution, managed FWD record, DNS cache and dynamic VPN address-list entries.
- Separately checks Windows TCP/443 to the hostname and directly to 1.1.1.1 to help distinguish DNS failure from general outbound connectivity failure.
- Redacts WireGuard private and preshared keys from operation logs and exported diagnostic evidence.

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
