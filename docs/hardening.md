# Hardening and side channels

## Side-channel protection (Whonix / Kicksecure parity)

`modules/side-channel.nix` layers Whonix's side-channel defenses on top of
the network anonymity. All verified booting on the hardened kernel in QEMU.

| Class              | Measure                                                                                                                                                                                        |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Microarchitectural | SMT disabled + full speculation mitigations (`nosmt`, `mds=full,nosmt`, `l1tf=full,force`, `tsx=off`, ...). SMT enables the L1TF/MDS/TAA cross-thread leak family.                             |
| Timing             | TCP timestamps off (kills remote uptime/clock-skew fingerprinting); boot-clock randomization (±15s, tunable); no clearnet NTP.                                                                 |
| DMA                | IOMMU forced + strict, early PCI DMA blocked, FireWire/Thunderbolt blacklisted.                                                                                                                |
| Memory disclosure  | `init_on_alloc/free=1`, `lockdown=confidentiality`, `perf_event_paranoid=3`, no coredumps. Stock kernel hardened via params/sysctls (nixpkgs dropped `linux-hardened`).                        |
| Attack surface     | Rare protocols + uncommon filesystems blacklisted; `kexec`/hibernation off; magic-sysrq off; `random.trust_cpu=off`; USBGuard blocks hot-plugged USB while unlocked; AppArmor on host + guest. |
| Heap               | hardened_malloc (GrapheneOS) as the gateway's global allocator.                                                                                                                                |
| Forensics          | Volatile logs (journald `Storage=volatile`, `/var/log` unpersisted); nothing survives a reboot.                                                                                                |
| Browser            | Workstation ships Tor Browser with `TOR_TRANSPROXY=1` (uniform fingerprint, uses the gateway's Tor).                                                                                           |
| Traffic analysis   | Tor seccomp sandbox, connection + circuit padding on, per-destination stream isolation.                                                                                                        |

Toggles (in `hosts/anon/default.nix` or per-host):

```nix
anon.sideChannel.disableSMT = true;                 # default; halves throughput on some CPUs
anon.sideChannel.hardenedMalloc = true;             # ON for the gateway (see below)
anon.sideChannel.bootClockRandomizationRange = 15;  # seconds
```

`hardenedMalloc` is on for the gateway but not inside the workstation guest,
where KDE and the toolkit are more likely to break under a strict allocator.
As a global `ld.so.preload` it can stall early boot in very minimal
environments (the QEMU `just vm` build forces it off). If the real gateway
misbehaves, set it to `false`.

**No `sdwdate`.** Whonix's Tor-fetched clock daemon is Debian-specific and
not in nixpkgs. The clock side channel is covered by disabled TCP timestamps,
boot-clock randomization and no NTP; keep the RTC roughly correct. Porting
sdwdate is the remaining gap versus full Whonix.

## Capability bounding

`modules/hardening.nix` strips `CAP_NET_ADMIN`, `CAP_NET_RAW`,
`CAP_NET_BROADCAST` and `CAP_SYS_MODULE` from every process tree that starts
an interactive session (getty, serial console, SSH, the greeter). The
bounding set only shrinks across fork/exec, so a login shell, and everything
it runs including setuid `doas`, cannot regain them. From a shell, even as
uid 0:

```sh
doas nft flush ruleset          # EPERM
doas wg-quick down wg-tunnel    # EPERM
doas ip route add default ...   # EPERM
doas insmod evil.ko             # EPERM
```

The bound is on login entry points only, so boot-time units that need these
caps (tor, WireGuard, nftables, the microVM host) are unaffected. To run such
a command on purpose, use the journal-logged systemd path (PID 1 keeps full
caps and grants them to the transient unit):

```sh
doas systemd-run -qt -p 'AmbientCapabilities=CAP_NET_ADMIN' \
  -p 'CapabilityBoundingSet=CAP_NET_ADMIN' nft list ruleset
```

> This is defense in depth, not a boundary. A root shell can still reach full
> caps through `systemd-run`/`systemctl` (the escape hatch above). It forces
> network and kernel reconfiguration off the ad-hoc root shell and onto a
> logged path, and it stops careless or scripted teardown, but a determined
> root on this box can still do it. Only a separate physical gateway removes
> that (see the [assurance ladder](workstation.md#workstation-persistence)).
> Combined with the amnesic root, any tamper is gone on the next reboot, and
> the box cannot persist a new config (see [updating](updating.md)).

## Design notes & caveats

- **Tor-over-VPN** hides Tor usage from your ISP and stops if either layer
  fails. It does not hide from your VPN provider that Tor is in use.
- **Updates never touch the anonymised uplink**; see [updating](updating.md).
  By default the box carries no nix at all and cannot mutate itself.
- **UDP can't be transparently torified** and is dropped (except DNS, which
  is redirected to Tor's DNSPort). Apps needing UDP won't work; that's
  intended.
- **QUIC / HTTP-3 (UDP 443) is blocked** (QUIC is UDP; Tor is TCP-only).
  Browsers fall back to TCP HTTP/2, which is torified. To avoid stalls while
  a browser probes QUIC, disable it: Firefox/Tor Browser
  `network.http.http3.enable = false`; Chromium `--disable-quic`.
- **No hostname on the LAN.** The WAN NIC uses `systemd-networkd` with
  `SendHostname=false` and a MAC-based client id; with per-boot MAC
  randomization the box presents no stable identifier.
- **Browser fingerprinting** is separate from network anonymity. Use Tor
  Browser for actual browsing; a transparent proxy does not anonymize your
  fingerprint.
- **Full amnesia:** to drop stable Tor guards and machine-id, comment out
  those entries in `modules/impermanence.nix`. The default keeps stable entry
  guards, as the Tor Project recommends.
- **Clock:** NTP is disabled to avoid a clearnet time leak; keep the RTC
  roughly correct.
