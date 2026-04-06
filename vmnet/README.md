# MacBox vmnet launchd package

This package turns the working vmnet helper into a LaunchDaemon-based service so
MacBox/86Box can stay unprivileged and connect to a root-owned helper over a
UNIX socket.

## Layout

- `src/vmnet_helper.m` - root helper that owns vmnet
- `src/vmnet_proto.h` - shared protocol/socket path
- `launchd/com.macbox.vmnethelper.plist` - LaunchDaemon plist
- `scripts/install-launchd.sh` - install and start service
- `scripts/uninstall-launchd.sh` - stop and remove service
- `scripts/status-launchd.sh` - quick status check

## Build

```bash
make clean
make
```

## Install

```bash
sudo ./scripts/install-launchd.sh
```

## Check status

```bash
./scripts/status-launchd.sh
```

## Remove

```bash
sudo ./scripts/uninstall-launchd.sh
```

## UI-supplied guest IP

`vmn_start_req_t` now includes a `guest_ip` field (IPv4 in network byte order). The helper no longer relies on a compiled-in guest IP.

- Shared / Host / Bridged modes: the helper accepts and logs `guest_ip` for future use.
- Published mode: `guest_ip` is required and is used when building PF/NAT rules.
