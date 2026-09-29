DHCPd-Guard - Updated Working Version

What was fixed:
- Removed seeded/demo leases, attack counts, events and activity values.
- Dashboard now starts at real runtime state: 0 active leases, 0 blocked attacks, no events.
- Fixed DHCP engine import/constructor mismatch.
- Fixed dashboard static-file loading.
- Fixed Security Rules API mismatch.
- Security rule toggles now persist in server memory and reflect their real state.
- Active Lease Renew/Revoke/Copy actions use the backend APIs.
- Client state tracking remains connected to DHCP packet processing and the lab transaction flow.
- Added simple login/logout flow.
- Added first-transition starvation/anomaly event when a client becomes SUSPICIOUS.
- Removed unsupported security-architecture claims from the dashboard.
- DHCP engine listens on UDP 6767 for the controlled lab implementation.

Login:
Username: admin
Password: admin123

Run:
1. Open PowerShell in this folder.
2. npm install   (only if node_modules is missing)
3. npm start
4. Open http://localhost:3000
5. Login with the credentials above.

Important:
This implementation listens on UDP 6767 and processes DHCP packets for the project lab. Standard DHCP clients normally use UDP 67/68, so do not deploy this as a competing DHCP server on a live network without an isolated lab setup and a complete DHCP response implementation.
