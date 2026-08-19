# Install

## Secrets (agenix)

Secrets are age-encrypted and committed to git in encrypted form. Plaintext
never enters the repo. At boot, agenix decrypts to `/run/agenix/` (tmpfs)
using a private identity on `/persist`, which survives the impermanence wipe.

```sh
# 1. On the target machine, create its identity and note the public key:
doas install -d -m 0700 /persist/secrets
doas age-keygen -o /persist/secrets/age-identity      # prints "Public key: age1..."

# 2. Put that public key (and your own admin key) into secrets/secrets.nix.

# 3. Encrypt your VPN's WireGuard private key into the repo:
cd secrets
nix run ..#agenix -- -e vpn-wg.key.age                # paste only the PrivateKey value
git add vpn-wg.key.age                                # safe: it's encrypted
```

## Deploy to real hardware

The disk layout is declarative (`modules/disk.nix`, via [disko]). There is no
`nixos-generate-config` and no hand-partitioning. The hardware config carries
only generic initrd storage drivers (SATA/NVMe/USB/virtio), so the same image
boots on essentially any x86_64 box. Fill in these before building:

1. **Target disk.** Set `disko.devices.disk.main.device` in `modules/disk.nix`
   (check with `lsblk`, e.g. `/dev/nvme0n1`). This is the disk the installer
   wipes.
2. **VPN.** Any WireGuard provider works (Mullvad, IVPN, ProtonVPN, AzireVPN,
   or one you host). Generate a WireGuard config and fill the non-secret
   values in `modules/vpn.nix`: `endpointIp`, `endpointPort`,
   `serverPublicKey`, `interfaceAddress`. Encrypt the private key with agenix
   (above); it never touches git in plaintext. (Mullvad example: log in at
   <https://mullvad.net> → Account → WireGuard configuration.)
3. **Age identity.** One file goes onto the encrypted `/persist` at install
   time (not into git, not into the ISO): the machine's age identity
   (`age-keygen -o age-identity`). Its public key goes into
   `secrets/secrets.nix`, and you re-encrypt the VPN key to it. Login
   passwords are prompted by the installer and hashed onto `/persist`.

Then build the live-USB installer (recommended, below) or, on an
already-running NixOS, `just check && doas nixos-rebuild switch --flake .#anon`.

## Live-USB install (offline)

`just iso` (or `nix build .#installer-iso`) builds a self-contained installer
ISO with the entire built `anon` system and the disko format script baked in.
It wipes the disk and installs fully offline: no network, no evaluation on the
target. Because the closure is baked in, steps 1 and 2 above must be done
first.

```sh
just iso                                   # -> result/iso/anon-installer.iso
doas dd if=result/iso/anon-installer.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

Boot the USB on the target (root autologin), put your `age-identity` somewhere
reachable (another USB, `/root`, ...), then:

```sh
install-anon /path/to/age-identity
# type ERASE to confirm. It prompts for the gateway ('anon') and workstation
# ('user') login passwords and the LUKS passphrase, wipes the disk, installs
# offline, and writes the secrets onto the encrypted /persist. Then reboot.
```

The installer touches nothing but the configured disk and bakes no secrets
into the ISO, so the ISO is safe to keep and reuse. On first boot you enter
the LUKS passphrase, then do the one-time [Secure Boot
enrollment](secure-boot.md).

## Verify anonymity after boot

```sh
curl https://check.torproject.org/api/ip     # should report IsTor: true

# Egress tripwire: the output chain logs anything it drops (rate-limited).
# Normally silent; any hit is worth a look. Logs are RAM-only, so live-monitor:
journalctl -kf -g KILLSWITCH-DROP
```

Interactive logins are capability-bounded (see [capability
bounding](hardening.md#capability-bounding)). A plain shell, even under
`doas`, lacks `CAP_NET_ADMIN`, so `nft`, `wg-quick`, `ip route` and `insmod`
fail with EPERM. This is deliberate: you cannot casually tear down the
killswitch from a root shell. To run such a command on purpose, use the
journal-logged systemd path:

```sh
# inspect the killswitch ruleset:
doas systemd-run -qt -p 'AmbientCapabilities=CAP_NET_ADMIN' \
  -p 'CapabilityBoundingSet=CAP_NET_ADMIN' nft list ruleset
# kill the tunnel and confirm nothing leaks (Tor is pinned to wg-tunnel):
doas systemd-run -qt -p 'AmbientCapabilities=CAP_NET_ADMIN' \
  -p 'CapabilityBoundingSet=CAP_NET_ADMIN' wg-quick down wg-tunnel
curl -m 5 https://example.com                    # must fail
```

[disko]: https://github.com/nix-community/disko
