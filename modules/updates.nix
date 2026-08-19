##############################################################################
# How this box gets Nix store paths (sealed appliance by default).
#
# Fetching from public infrastructure (cache.nixos.org, GitHub for flake
# inputs) is a side channel that no transport removes:
#   * It marks the client as a NixOS box. The "NixOS users" anonymity set is
#     tiny, so that fact alone narrows you considerably.
#   * The exact set of store paths fetched fingerprints your config.
# Routing the fetch over Tor only changes who sees it; it mixes a distinctive
# NixOS-shaped signal into the circuit you are trying to stay anonymous on.
# The fix is to keep the update channel off the anonymised uplink entirely.
#
# Default model: no substituters; the box receives a fully pre-built closure
# out of band (USB) and activates it offline, emitting nothing. Same philosophy
# as the offline installer. See docs/updating.md.
#
# The box cannot mutate itself: no Nix daemon and no nix/nixos-rebuild CLI
# (nix.enable = false). Updates come only from an external installer USB that
# writes the new closure to the target disk (Method A). Even a root compromise
# cannot activate a stripped generation; there is no tool on the box to do it,
# and the boot chain (Secure/Measured Boot, PCR 7+11) gates persistence.
# On-box updates (docs/updating.md Method B) are off by default; they are self-mutation.
#
# Escape hatch: anon.updates.allowOnlineFetch = true re-adds cache.nixos.org
# and routes fetches through Tor's SOCKS proxy. Still a side channel; enable
# only when you knowingly accept emitting "a Tor exit fetched NixOS packages".
# Opting into that (or localSubstituters) re-enables nix on the box, reopening
# the self-mutation channel the seal closes.
##############################################################################
{ config, lib, ... }:

let
  cfg = config.anon.updates;
  socksPort = 9050; # Tor SOCKS (see modules/tor-gateway.nix).
in {
  options.anon.updates = {
    allowOnlineFetch = lib.mkEnableOption ''
      fetching from public Nix substituters (cache.nixos.org) over the
      anonymised uplink, routed through Tor. Off by default: the box is a
      sealed appliance that takes closures out of band (see docs/updating.md). Still a
      side channel; only enable if you accept that'';

    localSubstituters = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "http://10.0.0.2:5000" ];
      description = ''
        Trusted binary caches on infrastructure you control (e.g. a LAN
        harmonia/nix-serve reachable via the lan-bypass). Used regardless of
        allowOnlineFetch; keeps the NixOS-usage signal on your own network.
        Add their public keys to nix.settings.trusted-public-keys and route to
        them via /persist/lan-bypass (see docs/workstation.md "Direct LAN access").
      '';
    };
  };

  config = lib.mkMerge [
    {
      # Sealed appliance: no nix daemon on the running box. Updates come only
      # from an external installer USB (Method A). Nix is re-enabled if you opt
      # into an on-box update channel (allowOnlineFetch / localSubstituters).
      # mkDefault so a host wanting Method B can set nix.enable = true.
      nix.enable = lib.mkDefault
        (cfg.allowOnlineFetch || cfg.localSubstituters != [ ]);

      # Never carry the public cache implicitly. A stray nixos-rebuild on the
      # box cannot silently reach cache.nixos.org over the uplink.
      nix.settings.substituters = lib.mkForce
        (cfg.localSubstituters
          ++ lib.optional cfg.allowOnlineFetch "https://cache.nixos.org");
      nix.settings.trusted-substituters = lib.mkForce cfg.localSubstituters;
    }

    # Route the daemon through Tor (socks5h: DNS also resolves at the exit);
    # fall back to building from source if the exit is blocked.
    (lib.mkIf cfg.allowOnlineFetch {
      systemd.services.nix-daemon.environment = {
        https_proxy = "socks5h://127.0.0.1:${toString socksPort}";
        http_proxy = "socks5h://127.0.0.1:${toString socksPort}";
        all_proxy = "socks5h://127.0.0.1:${toString socksPort}";
        no_proxy = "127.0.0.1,localhost,::1";
      };
      nix.settings.fallback = true;
    })
  ];
}
