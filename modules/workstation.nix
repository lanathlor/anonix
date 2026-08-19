##############################################################################
# Workstation microVM (Whonix-Workstation role).
#
# One network interface: a tap on the host's isolated virbr-anon bridge, which
# has no uplink. Its only next hop is the gateway (10.152.152.1), whose forward
# chain is drop and which only egresses via Tor.
#
# A clearnet leak is topologically impossible: the workstation has no path to
# the physical NIC. If Tor or the VPN on the gateway is down, the workstation's
# packets are dropped at the gateway. Root inside this VM cannot change that;
# only a hypervisor escape could.
#
# The system is amnesic (store shared read-only, root on tmpfs) except for
# /home, which is a persistent encrypted volume (see microvm.volumes). Crypto
# keys, passwords, and dev work live in $HOME and survive reboots; everything
# outside /home is wiped on boot. The backing image sits on the host's
# LUKS-encrypted /persist and is encrypted at rest.
##############################################################################
{ config, lib, pkgs, ... }:

let
  wsMac = "02:00:00:00:00:02";
  gatewayIp = "10.152.152.1";
  wsIp = "10.152.152.2";
in {
  imports = [ ./workstation-tools.nix ./workstation-desktop.nix ./workstation-crypto.nix ];

  microvm = {
    hypervisor = "qemu";
    vcpu = 2;
    # Not 2048: QEMU hangs on exactly 2 GiB (microvm.nix issue #171). Adjust.
    mem = 4096;

    # Read-only share of the host store; root stays on tmpfs => ephemeral.
    shares = [
      {
        tag = "ro-store";
        source = "/nix/store";
        mountPoint = "/nix/.ro-store";
        proto = "9p";
      }
      {
        # Host-provided login secret for `user`. The offline installer writes
        # the hash to /persist/ws-secrets on the host's LUKS-encrypted /persist;
        # exposing it read-only to the guest keeps it out of the world-readable
        # Nix store. Source dir created in modules/microvm-host.nix.
        tag = "ws-secrets";
        source = "/persist/ws-secrets";
        mountPoint = "/run/ws-secrets";
        proto = "9p";
      }
    ];

    # The only interface. tap `vm-anon-ws` is bridged into virbr-anon on the
    # host (see modules/microvm-host.nix). No user-net/WAN interface by design.
    interfaces = [{
      type = "tap";
      id = "vm-anon-ws";
      mac = wsMac;
    }];

    # Persistent /home: user data survives reboots while root stays tmpfs.
    # The backing image lives on the host's LUKS-encrypted /persist (dir created
    # in modules/microvm-host.nix); autoCreate makes an empty ext4 on first boot.
    # To isolate this data with a separate key (so unlocking the host's /persist
    # does not expose it), put LUKS inside the guest on this volume, at the cost
    # of a passphrase on the guest console. Adjust size (MiB) to taste.
    volumes = [{
      image = "/persist/microvms/workstation/home.img";
      mountPoint = "/home";
      size = 20480; # MiB (20 GiB)
      fsType = "ext4";
      autoCreate = true;
    }];
  };

  networking.hostName = "workstation";
  networking.useNetworkd = true;
  networking.useDHCP = false;
  services.resolved.enable = false;

  # Static config on the single interface; default route + DNS via the gateway.
  systemd.network.networks."10-int" = {
    matchConfig.MACAddress = wsMac;
    address = [ "${wsIp}/24" ];
    routes = [ { Gateway = gatewayIp; } ];
    networkConfig.DNS = gatewayIp;
  };
  networking.nameservers = [ gatewayIp ];

  ##########################################################################
  # No IPv6 (matches the gateway).
  ##########################################################################
  boot.kernel.sysctl = {
    "net.ipv6.conf.all.disable_ipv6" = 1;
    "net.ipv6.conf.default.disable_ipv6" = 1;
  };

  ##########################################################################
  # Modules VeraCrypt needs for deniable hidden-volume containers (see docs/workstation.md
  # "Plausible deniability"): dm-crypt, loop, and FUSE.
  ##########################################################################
  boot.kernelModules = [ "dm_crypt" "loop" "fuse" ];

  # Mandatory access control inside the guest too (contains the browser + tools).
  security.apparmor.enable = true;

  ##########################################################################
  # Rootless containers: `user` runs podman without root; each container gets
  # its own user namespace, so a breakout lands as an unprivileged user.
  # Container traffic still flows out the single interface to the gateway and
  # Tor. `docker` is aliased to podman.
  ##########################################################################
  virtualisation.podman = {
    enable = true;
    dockerCompat = true;
    defaultNetwork.settings.dns_enabled = true;
  };
  # Give `user` the subuid/subgid range rootless userns mapping needs.
  users.users.user.autoSubUidGidRange = true;

  ##########################################################################
  # Rootless Nix: the nix-daemon does the privileged work; `user` builds and
  # runs flakes without root. Flakes are enabled so `nix develop`/`nix run`
  # work out of the box. System activation still needs `doas nixos-rebuild`.
  ##########################################################################
  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    sandbox = true;
  };

  ##########################################################################
  # Rootless pentest tooling. Most recon/exploit tools run unprivileged (only
  # TCP connect traverses Tor). Packet capture is the exception: wireshark gives
  # dumpcap the capability and a `wireshark` group so capture works without root.
  # For anything that still needs privileges, use a rootless podman container.
  ##########################################################################
  programs.wireshark.enable = true;

  ##########################################################################
  # Belt-and-suspenders firewall: the workstation may talk only to the gateway.
  # (Redundant with having no other interface; defense in depth.)
  ##########################################################################
  networking.firewall.enable = false;
  networking.nftables.enable = true;
  networking.nftables.ruleset = ''
    table inet ws_fw {
      chain input {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state established,related accept
        ip saddr ${gatewayIp} accept
      }
      chain forward { type filter hook forward priority 0; policy drop; }
      chain output {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ct state established,related accept
        # All IPv4 egress is permitted here but can only reach the gateway
        # (the single interface). The gateway is the enforcement point: it
        # redirects TCP/DNS into Tor, forwards the @lan_bypass hosts, and drops
        # everything else. Keeping this permissive means the bypass is configured
        # on the gateway alone. IPv6 stays dropped (disabled; no v6 accept rule).
        meta nfproto ipv4 accept
      }
    }
  '';

  ##########################################################################
  # Normal user account. Everything is transparently torified by the gateway.
  ##########################################################################
  users.mutableUsers = false;
  users.users.user = {
    isNormalUser = true;
    # Login hash is not baked into the world-readable Nix store; it is read at
    # runtime from the read-only ws-secrets 9p share (/persist/ws-secrets on
    # the LUKS-encrypted /persist). The offline installer prompts for this
    # password and writes the hash, so it is unique per install.
    # If the file is absent the account is locked (fail-safe, not a leak);
    # recover by writing a hash to /persist/ws-secrets/user.passwd on the host
    # (`mkpasswd -m sha-512`). The guest has no network login, so exposure is
    # bounded regardless. Host-local readability of this hash is irrelevant: the
    # host can already read all guest data (/home lives on host /persist).
    hashedPasswordFile = "/run/ws-secrets/user.passwd";
    extraGroups = [ "wheel" "wireshark" ]; # wireshark => rootless packet capture
  };
  # doas instead of sudo (see hosts/anon/default.nix for rationale).
  security.sudo.enable = false;
  security.doas = {
    enable = true;
    # Reset the environment on escalation (doas default). keepEnv would carry
    # the caller's PATH/LD_PRELOAD into root, an escalation risk when `user`
    # runs offensive tooling whose output could poison the environment.
    extraRules = [{ groups = [ "wheel" ]; persist = true; }];
  };
  services.getty.autologinUser = lib.mkDefault null;

  # VeraCrypt (console mode): outer/hidden two-password containers for plausible
  # deniability (see docs/workstation.md "Plausible deniability"). cryptsetup covers the LUKS
  # detached-header alternative. The container is created by hand inside the
  # running workstation and is not declared in this repo: committing its
  # existence or structure to git would defeat deniability.
  # landrun: Landlock launcher for unprivileged, per-command sandboxing.
  # Wrap a risky tool so it can only touch what you grant:
  #   landrun --ro /nix --ro /etc --rw "$PWD" -- ./some-tool
  environment.systemPackages = with pkgs; [ curl torsocks git veracrypt cryptsetup landrun ];

  system.stateVersion = "26.05";
}
