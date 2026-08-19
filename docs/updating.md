# Updating (sealed appliance)

Fetching from `cache.nixos.org` is a side channel no transport removes. It
marks the client as a NixOS box, and the fetched store paths fingerprint your
exact config. Routing it over Tor only mixes that signal into your anonymity
circuit. So the box has no substituters. Updates are delivered as a pre-built
closure, out of band, and activated offline.

By default the running box also cannot mutate itself. It ships with no Nix
daemon and no `nix`/`nixos-rebuild` CLI (`nix.enable = false`), so nothing on
the box can build, copy, or switch a generation. Even a root compromise
cannot activate a security-stripped config. Updates come from outside only
(Method A). Both methods keep `/persist` (secrets, Secure Boot keys, Tor
guards, workstation `/home`, `lan-bypass`) intact.

## Method A: re-flash a newer installer USB (the default path)

Rebuild the ISO on your trusted builder with bumped inputs, write it to USB,
boot the target, and run `update-anon`. It detects the existing install, asks
for your LUKS passphrase, installs the USB's baked closure over the existing
`/nix`, points the system profile at it, and re-signs the bootloader. Nothing
is formatted.

```sh
# on the trusted builder, after `nix flake update`:
just iso
doas dd if=result/iso/anon-installer.iso of=/dev/sdX bs=4M status=progress oflag=sync
# boot the target on that USB (root autologin), then:
update-anon              # keep the current /persist/lan-bypass list
update-anon 10.0.0.2     # ... or replace it while updating
```

Roll back by choosing an older generation in the boot menu. (`install-anon`
warns instead of silently wiping a disk that already holds an anon install.)

## Method B: copy just the closure (opt-in; re-opens self-mutation)

> Warning: off by default. This runs `nix copy`/`nix-env`/
> `switch-to-configuration` on the running box, which the sealed default
> forbids. You must first re-enable nix on the box (`nix.enable = true` in
> `hosts/anon/default.nix`, or one of the `anon.updates.*` options below) and
> ship that config via Method A once. That lets the box, and anything that
> gains root on it, activate a new and possibly weakened generation of
> itself. Prefer Method A unless you accept that trade-off.

On a trusted builder, build the new system and copy its closure to a USB:

```sh
nixos-rebuild build --flake .#anon         # -> ./result (the toplevel)
nix copy --to file:///mnt/usb ./result     # closure -> USB (mount it first)
```

On the anon box, import and switch offline (nothing is fetched):

```sh
doas nix copy --no-check-sigs --from file:///mnt/usb <toplevel-store-path>
doas nix-env -p /nix/var/nix/profiles/system --set <toplevel-store-path>
doas <toplevel-store-path>/bin/switch-to-configuration switch   # reboot if the kernel changed
```

`<toplevel-store-path>` is what `readlink -f result` prints on the builder.
`--no-check-sigs` is fine because you built and carried it yourself. Never run
`nixos-rebuild switch --flake .#anon` on the box: evaluating the flake fetches
from GitHub, which re-opens the side channel this model closes.

## Opt-in variants

Both re-enable nix on the box:

- **Trusted LAN mirror.** Point `anon.updates.localSubstituters` at your own
  binary cache (harmonia/nix-serve) on a LAN host, add its key to
  `nix.settings.trusted-public-keys`, and route to it via `/persist/lan-bypass`
  (see [direct LAN access](workstation.md#direct-lan-access-split-tunnel-eg-a-local-llm)).
  Rebuilds then pull only from infrastructure you control, never Tor or the
  public cache.
- **Online fetch (not recommended).** `anon.updates.allowOnlineFetch = true`
  re-adds `cache.nixos.org` through Tor's SOCKS proxy. A Tor exit still sees
  a NixOS box fetching these paths; enable only if you accept that.
