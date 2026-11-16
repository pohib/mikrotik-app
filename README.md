# MikroTik VPN Manager — v1.10.0

## v1.10.0 — Detached topology workspace and theme fixes

- Fixed the LAN topology canvas background by applying the active theme to both the graphics scene and every attached view; Default is explicitly dark, Dark is charcoal and Light is pale.
- Added a separate resizable, maximizable topology window sharing the same live scene and selection with the embedded map.
- Added focus-selected, copy-selected-node details, double-click-to-center and synchronized detail panels.
- Reduced custom window minimize/maximize/close controls to compact 32×24 px buttons.

## v1.9.0 — Interactive LAN topology

- Reworked the LAN map into a more polished device canvas with larger cards, restrained gradients, clearer status colors and improved spacing.
- Added device selection: click a router, interface or endpoint to inspect the available IP, MAC, vendor, interface, discovery sources, last-seen time and radio details.
- Added live search across discovered device properties and filters for online, new/returned and missing devices.
- Kept inferred switch/AP links visually distinct from confirmed RouterOS interface and neighbor evidence. The map does not claim physical certainty where only MAC-table inference is available.
- Preserved IP Scan, DHCP, ARP, Bridge Host, Wi-Fi registration and LLDP/CDP/MNDP discovery inputs.

## v1.8.0 — Theme, settings and CI

- Fixed the application canvas background so Default, Dark and Light themes change the entire window, not only cards and the sidebar.
- Added explicit light/dark text palettes for headings, status labels, navigation, inputs, tables, checkboxes and secondary UI elements.
- Reworked **General settings**: confirmation before exit, local configuration-file path, LAN topology-history cleanup and one-click visual-preference reset.
- Improved LAN topology readability with wider device cards, more spacing, theme-aware canvas colors and bounded mouse-wheel zoom.
- Increased the baseline size of buttons, text inputs and selection controls while retaining compact map zoom buttons.
- Added automated unit and GUI smoke tests plus CI for Python 3.12/3.13 and Windows launcher validation.
- Runtime dependencies are pinned to PySide6 6.12.0 and Paramiko 4.0.0. Python 3.10–3.13 is supported; Python 3.13.13 is the recommended runtime.


## v1.7.0 — Grouped service dependency discovery

- Replaced manual DNS observation as the primary discovery path with an explicit **Update dependencies** workflow.
- Added passive subdomain candidates from Certificate Transparency (crt.sh), followed by A/AAAA/CNAME lookups through Cloudflare DNS-over-HTTPS. The scan runs in a background worker and does not change router DNS settings.
- Replaced the flat discovery table with an expandable hierarchy: service group → domains → resolved IP addresses. Added group/domain checkboxes, a search filter across groups/domains/IPs, and expand/collapse controls. Group assignments are also shown in the routing-target table and stored locally in application settings.
- Added confidence/source labels: actual browser requests from HAR, discovered CT/DNS names, and built-in profile entries.
- HAR import groups request hosts, related Referer/Origin/Location hosts, redirects, and request-associated server IPs.
- Resolved IPs remain informational and are not added to routing by default. IPv4 /32 addition is an explicit checkbox; shared CDN addresses may serve unrelated services.
- Manual DNS-cache import/observation remains available as an optional secondary source. It is clearly marked as not attributing queries to a particular LAN client or application.
- Fixed the apply-changes preview dialog by styling its dialog and scroll-content surfaces explicitly, including the scroll area's child widget, to prevent Windows' default white background from showing through.

### Discovery limitations

Certificate Transparency only contains hostnames observed in issued certificates; it is not a complete service inventory. Public DNS answers can vary by resolver, geography, and time. HAR is the best source in this workflow for confirming that a browser actually requested a hostname, but only covers the captured browser session. DNS-derived IPs may be shared CDN/hosting addresses and should not automatically be treated as exclusive to one service.

## v1.6.0 — Dialog UI and routing diagnostics

- All application-owned secondary windows use frameless dark styling with a custom draggable title bar and close control.
- Message boxes use the application theme; file pickers use themed Qt dialogs.
- Expanded IPv6 inspection and FastTrack analysis. These checks are read-only and report possible VPN bypass conditions without changing router configuration.
- Domain route lookup inspects resolved addresses, DNS cache, managed address-list entries, and active routes in both main and VPN tables.
- Client checks include conntrack, FastTrack/Mangle counters, and IPv6 neighbor evidence. A conntrack snapshot is point-in-time evidence, not proof that every packet followed the expected path.

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
