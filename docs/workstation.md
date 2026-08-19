# Gateway / workstation isolation

A firewall killswitch is software policy. A kernel bug or root compromise
could still leak, because the machine has a wire to the internet. To make a
leak physically impossible, the machine is split Whonix-style:

```
physical NIC ── Gateway/host (Tor + VPN + killswitch)
                       │ virbr-anon 10.152.152.1/24 (isolated bridge, no uplink)
                       ▼
              Workstation microVM (10.152.152.2), its only interface
```

- The gateway is the physical machine (`hosts/anon`). It owns the NIC and
  runs the Tor+VPN+killswitch stack. Its `forward` chain is `drop`, so it
  never routes anything to the WAN; workstation traffic can only be redirected
  into Tor.
- The workstation (`modules/workstation.nix`) is a microVM whose single
  interface is on the isolated bridge. It has no path to the physical NIC, so
  root inside it cannot leak; only a hypervisor escape could. Its system is
  amnesic (root on tmpfs) except `/home`, which persists (below).

If Tor is down, the gateway drops the workstation's packets. If the VPN is
down, Tor cannot egress. Either way there is no second route to remove,
because there never was one. You do your actual work in the workstation:

```sh
doas microvm -l                       # list running microVMs
doas microvm -c workstation           # console into it (login user/nixos)
# inside, everything is torified; try `curl https://check.torproject.org/api/ip`
```

Toggle the split with `anon.workstation.enable` (default true). With it off
you get a single-box gateway with the software killswitch only. The microVM
needs KVM; the plain `just vm` smoke test disables it (no nested virt).

## Workstation persistence

The workstation's `/home` is a persistent, encrypted virtio disk. Your keys
(`~/.ssh`, `~/.gnupg`), password store and dev work survive reboots. The rest
of the system stays amnesic.

- It is an auto-created image (ext4, 20 GiB default) at
  `/persist/microvms/workstation/home.img` on the host's LUKS-encrypted
  `/persist`, so it is encrypted at rest. Tune `size` in
  `modules/workstation.nix`.
- Trade-off: a persistent `$HOME` can hold identifying state, so treat the
  disk as sensitive. The host can read the workstation's data, since the
  image sits on the host. If you want isolation from the host too, run LUKS
  inside the guest on this volume; the cost is unlocking it on the guest
  console each boot.

> Assurance ladder: single-box killswitch < this (leak-proof unless hypervisor
> escape) < separate physical gateway device. This repo implements rung 2;
> rung 3 is the same gateway config flashed to a second box.

## Plausible deniability (hidden volumes)

`/home` gives confidentiality. For your most sensitive data you may also want
deniability, so an adversary cannot prove the data exists. The workstation
ships VeraCrypt (console mode) and `cryptsetup`.

> Warning: deniability is narrow and easily lost.
>
> - It does not defeat a coercer who knows hidden volumes exist and keeps
>   demanding passwords. It only helps where revealing a decoy ends the
>   demand.
> - Artifacts betray hidden volumes more often than the crypto fails:
>   recent-files lists, shell history, mount logs, `~/.config` pointers. The
>   amnesic root helps, but the decoy `/home` still accumulates traces.
> - Never keep backups or snapshots of the container taken at different
>   times. Diffing them proves writes into the "free space".
> - A pristine decoy is suspicious; actually use it.
> - Mounting the outer volume without protect-hidden mode can destroy the
>   hidden volume.

The container is created by hand inside the workstation. It is deliberately
not declared in this repo. Layered concession points, innermost is deniable:

1. Host `/persist` LUKS passphrase: boots the machine.
2. Workstation `/home`: your everyday dev env (the believable decoy).
3. A VeraCrypt outer volume in `/home`: plausible secrets you'd concede.
4. The hidden volume inside it: the data you deny exists.

Create it in the running workstation, under `doas` (mapping needs root):

```sh
# Interactive wizard: choose "Hidden VeraCrypt volume", pick an innocuous path
# (e.g. ~/Documents/media.dat), set different outer and hidden passwords.
veracrypt -t -c ~/Documents/media.dat

veracrypt -t ~/Documents/media.dat /mnt/decoy    # mount decoy (outer password)
veracrypt -t ~/Documents/media.dat /mnt/secret   # mount hidden (hidden password)
# when writing to the decoy, protect the hidden volume:
veracrypt -t --protect-hidden=yes ~/Documents/media.dat /mnt/decoy
veracrypt -t -d            # dismount all
```

Keep the hidden volume mounted only while in use; the amnesic root wipes mount
state on reboot. The container file lives in the persistent `/home`.

## Workstation toolkit (dev + recon/exploit)

`modules/workstation-tools.nix` installs a dev and offensive-security
toolchain in the workstation only, never the gateway. Toggle off for a lean
image: `anon.workstation.toolkit.enable = false;`.

- Languages/build: Python (`pwntools`, `impacket`, `scapy`, `uv`, `pipx`,
  `virtualenv`), Node.js + `pnpm`/`yarn`, Go + `gopls`,
  `gcc`/`make`/`binutils`/`nasm`, `opencode` (AI coding agent).
- Recon: `nmap`, `amass`, `subfinder`, `dnsx`, `httpx`, `nuclei`, `ffuf`,
  `gobuster`, `feroxbuster`, `dirb`, `wfuzz`, `nikto`, `whatweb`, `wafw00f`,
  `wpscan`, `katana`, `gau`, `waybackurls`, `theHarvester`, `recon-ng`,
  `seclists`.
- Exploitation: `metasploit`, `sqlmap`, `hydra`, `netexec`, `john`,
  `exploitdb` (`searchsploit`). (`hashcat` is temporarily removed — three
  unfixed critical buffer overflows in v7.1.2; `john` covers CPU cracking.)
- Reversing/utils: `gdb`, `radare2`, `binwalk`, `ltrace`/`strace`, `socat`,
  `nc`, `tcpdump`, `termshark`.

> Authorized use only; everything exits from a shared Tor exit IP. The
> toolkit also behaves differently from Kali, because all traffic is forced
> through Tor:
>
> - Only TCP `connect()` traverses Tor: no SYN/UDP/ACK scans, no ICMP/ping.
>   Use `nmap -sT -Pn -n`. Expect it slow, and the exit may be blocked.
> - UDP is dropped (except DNS via Tor). Raw-packet tools are left out.
> - No inbound from the clearnet: you can't catch a reverse shell from an
>   arbitrary host. Use a Tor onion service as the listener, or a bind shell.

The toolkit is large and baked into the offline ISO; disable it for a small
image.

**Least privilege.** The VM runs as the unprivileged `microvm` user on the
host, so a VM escape lands unprivileged, not root on the gateway. Inside the
guest: rootless Podman (`docker` is aliased to it), rootless Nix (`nix
develop` etc. without root), rootless packet capture (`dumpcap` capability +
`wireshark` group), and `doas` instead of `sudo` everywhere (a small,
auditable SUID binary, wheel-only).

**Landlock** is active (`lsm=landlock,yama,apparmor,bpf`) and adds
unprivileged per-command sandboxing on top. Wrap risky tools with `landrun`
so an exploit can't reach the rest of `$HOME`:

```sh
landrun --ro /nix --ro /etc --rw "$PWD" -- ./some-tool   # FS-restricted, no root
```

It is opt-in: it only sandboxes what you wrap.

## Crypto wallets (Monero + Bitcoin)

`modules/workstation-crypto.nix` installs two GUI wallets in the workstation
(they need the KDE desktop, below). Toggle off:
`anon.workstation.crypto.enable = false;`.

- Feather: a lightweight, Tor-native Monero wallet.
- Sparrow: a privacy-focused Bitcoin wallet (your own node or an onion
  Electrum server).

Both store keys under `$HOME` (`~/Monero/wallets`, `~/.sparrow/wallets`),
which lives on the persistent encrypted `/home` volume, so keys survive
reboots. The module pre-creates those directories with `0700` perms. The
wallet password is what guards the keys if the `/home` image is ever read, so
set a strong one. For deniability, keep a wallet inside a VeraCrypt hidden
volume (above).

> Warning: only `/home` persists. A wallet saved anywhere else is lost on
> reboot, and lost wallet means lost funds. Back up your seed phrase offline
> regardless; a single encrypted disk image is not a backup.

> Set each wallet's proxy to "None"; do not enable its bundled Tor. The
> workstation is already torified, and the gateway resolves and routes
> `.onion` addresses (`AutomapHostsOnResolve`). A wallet running its own Tor
> would be Tor-over-Tor: slow and worse for anonymity. With the proxy off,
> the wallet connects "directly", the gateway torifies it, and onion nodes
> still work.
>
> - Feather: Settings → Network → Proxy: None.
> - Sparrow: Preferences → Server, leave "Use Proxy" off; point it at an
>   Electrum server (onion works) or your own node.
> - A misconfigured wallet cannot leak. The killswitch drops anything
>   non-torifiable, so it just fails to connect.

**No decentralized exchange (Bisq).** nixpkgs only has Bisq 2, which
hardcodes its own co-located Tor (`127.0.0.1` control channel and onion
target). It cannot use the gateway's Tor and would run Tor-over-Tor. That
trade-off was declined; revisit `modules/workstation-crypto.nix` if you
decide it is acceptable.

## KDE Plasma desktop

A KDE Plasma 6 + SDDM desktop runs inside the workstation microVM, never on
the gateway. Everything it does is torified.

- `modules/workstation-desktop.nix` (guest): Plasma 6, SDDM, PipeWire, and a
  virtio-GPU exported over a SPICE unix socket. Resources are bumped to
  8 GiB / 4 vCPU; tune to your host.
- `modules/workstation-viewer.nix` (host): the gateway's only GUI, a minimal
  Wayland kiosk (`cage`) showing the SPICE display fullscreen
  (`remote-viewer`). A `tuigreet` greeter prompts for the gateway login
  (`anon`) first; there is no auto-login. Boot → gateway greeter →
  workstation SDDM → Plasma.

```nix
anon.workstation.desktop.enable = true;   # KDE in the guest (default)
anon.workstation.viewer.enable  = true;   # host thin-client that shows it
```

Set both `false` for a headless setup (much smaller image) and use
`doas microvm -c workstation` instead.

> The display path (GPU drivers, GL-accelerated SPICE, KVM, cage, socket
> permissions) is inherently runtime. It builds cleanly, but expect to tune
> it on real hardware. The SPICE socket is chowned to `anon` by a `.path`
> unit after the VM starts; on a black screen, try
> `remote-viewer spice+unix:///var/lib/microvms/workstation/spice.sock` by
> hand. The viewer runs as `anon` behind an interactive login, but the GUI is
> still added attack surface on the gateway, and Plasma is a large closure
> baked into the ISO.

## Direct LAN access (split-tunnel, e.g. a local LLM)

By default the workstation can reach nothing but Tor. To let it reach a host
on your LAN directly (typically a local LLM/API you run yourself), list IPs
in a plain file on the encrypted `/persist`: `/persist/lan-bypass` (one IPv4
per line, `#` comments allowed). This is configured at install time or
runtime, not baked into the build.

```sh
# from the live ISO:
install-anon age-identity 10.0.0.2       # 10.0.0.2 = your local LLM

# or later, on the running box (no rebuild):
echo 10.0.0.2 | doas tee /persist/lan-bypass
doas systemctl restart lan-bypass        # applies immediately; empty file = off
```

At boot, `lan-bypass.service` fills the nftables `lan_bypass` set from the
file and enables forwarding, but only if the file lists hosts. The gateway
then skips the Tor redirect for those IPs and masquerades them out the
physical NIC. Inside the workstation, use the raw IP
(`curl http://10.0.0.2:11434/api/tags`); DNS still resolves through Tor.

> Warning: this is a deliberate exception to the "everything via Tor" design.
> Traffic to these IPs is not anonymised and bypasses both Tor and the VPN
> (it works even with the tunnel down). It is scoped tight: only the listed
> IPs, outbound only, not the rest of the LAN. Keep the list minimal and only
> for hosts you fully control. Empty or remove the file (and restart the
> service) to return to fully torified.
