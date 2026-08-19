# anonix

A NixOS flake for maximal anonymity. Every application is forced through Tor,
Tor rides a WireGuard VPN tunnel, and the firewall drops everything else. If
either layer is down, no packet leaves the machine.

The VPN is any WireGuard provider you choose (Mullvad, IVPN, ProtonVPN,
AzireVPN, or a WireGuard server you host yourself) — see [VPN setup](#vpn-setup-required)
below. Mullvad is used as the running example.

- **Transparent Tor gateway.** All TCP and DNS is redirected into Tor. There
  is no way to send unproxied traffic.
- **Tor-over-VPN.** Your ISP sees only WireGuard to your VPN endpoint, never
  Tor or clearnet.
- **Hard killswitch.** The firewall drops by default. The only allowed egress
  is the Tor daemon's own sockets, pinned to `wg-tunnel`, plus the encrypted
  WireGuard packets to the VPN endpoint. If the tunnel drops, Tor's packets are
  dropped too; they cannot fall back to the physical NIC. No IPv6, no stray
  UDP, no clearnet Tor.
- **Impermanence.** Root is tmpfs and wiped every boot. Only a short list of
  paths under `/persist` survives.
- **Encrypted at rest.** `/nix` and `/persist` are LUKS-encrypted. Imaging the
  disk yields no age identity, Secure Boot keys, Tor guards, or logs.
- **Managed Secure Boot.** lanzaboote signs kernel and initrd with your own
  keys, auto-generated on `/persist` and auto-enrolled.
- **Gateway/workstation isolation.** Apps run in a workstation microVM with no
  route to the physical NIC. A clearnet leak is topologically impossible, not
  just firewalled off.

```
apps ─▶ Tor (transparent proxy) ─▶ VPN tunnel ─▶ Tor guard ─▶ Tor net ─▶ exit ─▶ Internet
       (nft nat redirect)          (default route)   (as user `tor`)
```

## VPN setup (required)

The VPN tunnel is **required** — it is the transport Tor rides, and the
killswitch is built around it (Tor may only egress on the `wg-tunnel`
interface). What you choose is the _provider_: any WireGuard endpoint works.
Fill four non-secret values plus the encrypted private key in
`modules/vpn.nix`, under the `anon.vpn` options:

```nix
anon.vpn.endpointIp       = "193.138.7.100";   # [Peer]      Endpoint IP
anon.vpn.endpointPort     = 51820;             # [Peer]      Endpoint port
anon.vpn.serverPublicKey  = "…=";              # [Peer]      PublicKey
anon.vpn.interfaceAddress = [ "10.64.0.2/32" ]; # [Interface] Address
# privateKeyFile defaults to the agenix-decrypted key (see docs/install.md).
```

Any provider that hands you a WireGuard `.conf` gives every value above.
**Mullvad example:** log in at <https://mullvad.net> → Account → WireGuard
configuration, generate a config, and copy the four values from it. IVPN,
ProtonVPN, AzireVPN, or a WireGuard server you host yourself work identically.
Encrypt the private key with agenix (it never enters git in plaintext); the
full flow is in [docs/install.md](docs/install.md).

> **WireGuard only, by design.** A kernel-level named interface is what lets
> the killswitch pin egress with one nftables rule and no mutable daemon
> state. OpenVPN or an app-based commercial VPN daemon would reintroduce
> exactly the state and process-egress complexity this design closes off, so
> they are deliberately out of scope.

## Threat model

Defends against:

- **Your ISP or local network observer.** Sees only WireGuard to your VPN
  endpoint. No Tor, no clearnet, no hostname, per-boot random MAC.
- **Application and OS-level leaks.** Default-drop killswitch on the gateway;
  the workstation has no route to the physical NIC at all.
- **Disk theft or imaging.** LUKS on `/nix` and `/persist`, amnesic tmpfs
  root, RAM-only logs.
- **Boot-chain tampering (evil maid).** Own-key Secure Boot; TPM2 unlock
  sealed to PCR 7+11 falls back to the passphrase if the chain changes.
- **Careless or scripted killswitch teardown.** Interactive shells (even root)
  lack the capabilities; the only path is deliberate and journal-logged.
- **Coerced unlock.** Optional duress passphrase crypto-erases `/persist` and
  boots a working decoy. Deniable to someone watching you boot, not to
  offline forensics (the second keyslot is visible).

Out of scope:

- **Traffic correlation** by a global passive adversary, or your VPN provider
  and a Tor exit working together.
- **What the endpoints see.** Your VPN provider knows a Tor user; the Tor exit
  sees your traffic (use end-to-end encryption); visited sites can fingerprint
  a non-Tor-Browser browser.
- **Hypervisor escape.** Then the attacker is on the gateway; the physical
  killswitch still holds, but isolation is gone. The next rung is a separate
  physical gateway box.
- **A determined root on the gateway.** The capability bound is depth, not a
  boundary; `systemd-run` reaches full capabilities (logged, and amnesia
  clears tamper on reboot).
- **Firmware below UEFI, hardware implants, and your own opsec** (LAN-bypass
  hosts you add, what you keep in the persistent `/home`, wallet backups).

## Why not Whonix, Tails, or Qubes?

All three are mature, heavily scrutinized projects — if one of them fits your
threat model, use it. anonix exists because none of them combines these
properties:

- **The whole system is one declarative flake.** Every claim in this README
  traces to a line of Nix you can read, and two builds from the same commit
  are bit-for-bit the same system. Whonix and Tails are curated Debian images
  you trust as artifacts; here the artifact is derived from the config in
  front of you, and drift is a merge conflict, not a mystery.
- **Security claims are machine-checked.** The killswitch, leak containment,
  isolation, duress wipe, and update behavior are proven by VM tests on every
  commit (see [the table below](#what-is-verified-what-is-untested),
  including what is *not* proven). The other projects are certainly tested,
  but don't ship an automated "these properties hold on this exact build"
  gate you can re-run yourself.
- **Tor-over-VPN is the architecture, not an option.** Whonix and Tails can
  be combined with a VPN, with well-documented caveats and manual setup.
  Here the WireGuard tunnel is the only surface Tor may egress on, enforced
  by one nftables rule: your ISP never sees Tor, and there is no
  configuration in which it could.
- **Gateway/workstation isolation on one machine, without a desktop
  hypervisor stack.** Whonix's two-VM split needs VirtualBox/KVM on a host
  OS you also have to trust; Qubes does it best but demands dedicated,
  well-supported hardware. anonix runs the workstation as a microVM on a
  minimal NixOS gateway host — smaller than Qubes, more integrated than
  Whonix-on-a-laptop.
- **Amnesia with a sealed boot chain.** Tails is amnesic but lives on a USB
  stick with no Secure Boot story of your own. anonix wipes root every boot
  *and* signs the kernel with your own keys, seals unlock to the TPM, and
  offers a duress passphrase that crypto-erases `/persist`.

Honest trade-offs the other way: Whonix has had years of adversarial review
that a young project cannot claim; Qubes' Xen-based compartmentalization is a
stronger isolation boundary than a microVM on a shared kernel's hypervisor;
and Tails' leave-no-trace-on-borrowed-hardware model is out of scope here —
anonix assumes a machine you own and installed on.

## Documentation

| Doc                                        | Contents                                                                                                |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| [docs/install.md](docs/install.md)         | Secrets (agenix), hardware prep, offline live-USB install, first-boot verification                      |
| [docs/updating.md](docs/updating.md)       | The sealed-appliance update model: USB re-flash, offline closure copy, opt-in variants                  |
| [docs/workstation.md](docs/workstation.md) | The microVM split, persistent `/home`, hidden volumes, toolkit, crypto wallets, KDE desktop, LAN bypass |
| [docs/secure-boot.md](docs/secure-boot.md) | Managed Secure Boot (lanzaboote) and TPM2 measured-boot unlock                                          |
| [docs/hardening.md](docs/hardening.md)     | Side-channel defenses, capability bounding, design notes and caveats                                    |

## Layout

```
flake.nix                      # inputs, the `anon` host, installer ISO, install/update scripts
justfile                       # check / build / vm / iso / switch
docs/                          # documentation (see table above)
hosts/anon/
  default.nix                  # host wiring, users, bootloader, QEMU vmVariant
  hardware-configuration.nix   # generic initrd storage drivers (no nixos-generate-config)
modules/
  disk.nix                     # disko: declarative GPT + LUKS + tmpfs layout
  tor-gateway.nix              # Tor transparent proxy + nftables killswitch (the core)
  vpn.nix                      # WireGuard VPN full tunnel, any provider (raw wg-quick)
  secrets.nix                  # agenix wiring (identity on /persist)
  impermanence.nix             # tmpfs root + the /persist keep-list
  hardening.nix                # MAC randomization, sysctls, capability bounding
  side-channel.nix             # Whonix/Kicksecure-style side-channel protection
  secure-boot.nix              # managed UEFI Secure Boot (lanzaboote) + TPM2 unlock
  admin.nix                    # immutable users, locked root, doas instead of sudo
  duress.nix                   # duress passphrase: crypto-erases /persist, boots a decoy
  updates.nix                  # sealed-appliance update policy (no substituters)
  persist-provision.nix        # makes a wiped/fresh /persist boot into a working system
  persist-provision-script.nix # the provisioning script itself, shared with the tests
  microvm-host.nix             # microVM host wiring + always-networkd WAN
  workstation.nix              # workstation microVM (persistent /home, VeraCrypt)
  workstation-tools.nix        # dev + recon/exploit toolkit (toggle)
  workstation-crypto.nix       # Monero (Feather) + Bitcoin (Sparrow) wallets (toggle)
  workstation-desktop.nix      # KDE Plasma 6 in the workstation, over SPICE (toggle)
  workstation-viewer.nix       # host thin-client kiosk that displays it (toggle)
secrets/
  secrets.nix                  # agenix rules: which keys decrypt which secret
  vpn-wg.key.age               # placeholder encrypted VPN key (you re-create it)
tests/                         # NixOS VM tests: killswitch, leaks, duress, updates, ...
```

## Try it in QEMU

```sh
just vm          # or: nix run nixpkgs#just -- vm
```

The VM boots to a login prompt (`anon` / password `nixos`). It has no real
VPN key, so the tunnel never comes up and the killswitch keeps the guest
offline. That is expected. Log in and inspect:

```sh
systemctl status tor
ip route                  # no working default route without the tunnel
# nft needs CAP_NET_ADMIN, which interactive shells are bounded out of
# (see docs/hardening.md); read the ruleset via the deliberate path:
doas systemd-run -qt -p 'AmbientCapabilities=CAP_NET_ADMIN' \
  -p 'CapabilityBoundingSet=CAP_NET_ADMIN' nft list ruleset
```

Quit QEMU with `Ctrl-a x`.

## Install on real hardware

Three inputs, then one command; see [docs/install.md](docs/install.md) for
the details:

1. Set the target disk in `modules/disk.nix`.
2. Fill your VPN's WireGuard values in `modules/vpn.nix` and encrypt the
   private key with agenix (see [VPN setup](#vpn-setup-required); Mullvad is
   the running example, any WireGuard provider works).
3. Create the machine's age identity and register its public key in
   `secrets/secrets.nix`.

Then `just iso`, write the ISO to a USB stick, boot the target, and run
`install-anon <age-identity>`. The install is fully offline. Updates work the
same way (re-flash and run `update-anon`); see
[docs/updating.md](docs/updating.md).

## What is verified, what is untested

Every security claim above is either machine-checked or listed here as
untested. `just check` runs the eval checks; the VM tests run in QEMU.

Verified:

| Claim                                                                                             | How                                                                    |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Killswitch stays fail-closed when Tor alone or the VPN alone dies                                 | VM test `killswitch-egress`                                            |
| Tunnel up: only encrypted WireGuard leaves the box (no plaintext DNS/TCP/ICMP)                    | VM test `no-clearnet-leak`                                             |
| Gateway down: the workstation loses all connectivity (no second route)                            | VM test `killswitch-gateway-down`                                      |
| No key: nothing egresses; ruleset matches design; IPv6 off; no sudo, root locked, doas wheel-only | VM test `gateway-security`                                             |
| Gateway return traffic to the workstation is permitted (regression)                               | VM test `workstation-return` + eval check `workstation-return-ruleset` |
| Duress passphrase crypto-erases `/persist`, decoy boots and logs in, no forensic trace            | VM test `duress-wipes-persist`                                         |
| `update-anon` mechanism keeps `/persist` and retains the old generation                           | VM test `update-keeps-persist`                                         |
| Locked root, immutable users, and other option-level invariants can't drift                       | eval check `anon-security-invariants`                                  |
| Side-channel kernel params boot on the hardened kernel                                            | QEMU boot (`just vm`)                                                  |

Untested (builds and evaluates, but not proven by a test):

| Claim                                                | Why untested                                                          |
| ---------------------------------------------------- | --------------------------------------------------------------------- |
| Traffic actually exits through a working Tor circuit | needs a live network; the VM tests prove containment, not the circuit |
| Secure Boot enrollment and TPM2 PCR 7+11 unlock      | needs real UEFI firmware and a TPM                                    |
| lanzaboote re-sign path during `update-anon`         | not covered by the update test                                        |
| Duress passphrase through the real initrd prompt     | test drives the mechanism directly, not the initrd                    |
| SPICE desktop/viewer display path                    | inherently runtime; expect tuning on real hardware                    |
| `hardened_malloc` on a real gateway's early boot     | forced off in the QEMU smoke test                                     |

## Continuous integration

GitHub Actions ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs on
every push and pull request. `just ci` runs the same pipeline locally
(`just ci-tcg` on a machine without `/dev/kvm`: the VM tests then run under
QEMU TCG software emulation via `just test-tcg`):

- **Lint**: `statix` and `deadnix` (same pins and config as `just lint`;
  disabled style lints are documented in `statix.toml`).
- **Tests**: every flake check, auto-discovered, one runner job each, with
  KVM enabled on the GitHub runners.
- **ISO**: builds `.#installer-iso-ci` (`just iso-ci`) — the offline installer
  baking the anon closure with _dummy_ VPN values, since the real endpoint and
  key are secrets and never in git. The ISO is uploaded as a workflow artifact,
  and attached to the GitHub release on `v*` tags. A system installed from it
  stays offline by design (the killswitch holds without a working tunnel); it
  is a build-proof and demo image, not a deployable one. For real hardware,
  build `.#installer-iso` locally with your values filled in.
- **SBOM + CVE audit**: `sbomnix` generates SPDX and CycloneDX SBOMs of the
  full system closure (`.#anon-ci-system`), and `grype` scans the SBOM for
  known CVEs (`just sbom` / `just audit` locally). The audit **fails on any
  Critical finding**; triage by bumping the nixpkgs pin or by adding a
  documented ignore entry to `.grype.yaml` (grype's CPE matching against Nix
  attribute names does produce false positives). A severity summary lands in
  the job summary; full results and the SBOMs are uploaded as artifacts and
  attached to releases.

## License

[MIT](LICENSE).
