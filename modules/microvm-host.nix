##############################################################################
# microVM host wiring (Whonix gateway/workstation split, one physical machine).
#
# This machine is the gateway (owns the physical NIC, runs Tor + VPN +
# killswitch) and also the microVM host running the isolated `workstation`
# microVM.
#
# The internal bridge `virbr-anon` connects only the host and the workstation
# tap. It has no uplink and the host never forwards or NATs it (FORWARD is
# drop in the gateway firewall). The workstation can reach exactly one thing:
# this gateway's Tor.
#
#            physical NIC ── Gateway/host (Tor + VPN, killswitch)
#                                     │ virbr-anon 10.152.152.1/24 (no uplink)
#                                     ▼
#                            workstation microVM (10.152.152.2, one NIC)
##############################################################################
{ config, lib, pkgs, ... }:

let
  cfg = config.anon.workstation;
in {
  options.anon.workstation = {
    enable = lib.mkEnableOption "the isolated workstation microVM (Whonix-style)" // {
      default = true;
    };

    # These two mirror options defined inside the guest system
    # (workstation-desktop.nix / workstation-tools.nix). microvm.nix builds
    # the guest as a separate NixOS system, so setting the guest's options
    # from hosts/anon/default.nix never reaches it. We declare host-level
    # toggles here and forward their values into the guest (see microvm.vms
    # below), so the anon.workstation.desktop.enable and
    # .toolkit.enable toggles work from the host config.
    desktop.enable = lib.mkEnableOption "the KDE Plasma 6 desktop inside the workstation microVM" // {
      default = true;
    };
    toolkit.enable = lib.mkEnableOption "the dev + recon/exploit toolkit inside the workstation microVM" // {
      default = true;
    };
    crypto.enable = lib.mkEnableOption "Monero (Feather) + Bitcoin (Sparrow) wallets inside the workstation microVM" // {
      default = true;
    };
  };

  config = lib.mkMerge [
    ########################################################################
    # WAN networking is always via systemd-networkd, whether or not the
    # workstation microVM is enabled. This guarantees one consistent,
    # hardened DHCP client on the physical NIC (SendHostname=false), so
    # single-box mode does not fall back to dhcpcd, which cannot be reliably
    # told to stop leaking our hostname to the LAN.
    ########################################################################
    {
      networking.useNetworkd = true;
      networking.useDHCP = false;

      # Physical WAN NIC(s): DHCP for a LAN address (only WireGuard leaves).
      systemd.network.networks."30-wan" = {
        matchConfig.Name = "en* eth* wl*";
        networkConfig.DHCP = "ipv4";
        linkConfig.RequiredForOnline = "routable";
        # Never disclose our hostname ("anon") to the DHCP server or the
        # local network. Combined with the per-boot random MAC (hardening.nix)
        # the box presents no stable identifier to the LAN it joins.
        dhcpV4Config = {
          SendHostname = false;
          ClientIdentifier = "mac";
        };
      };
    }

    ########################################################################
    # microVM host: only when the isolated workstation is enabled.
    ########################################################################
    (lib.mkIf cfg.enable {
      microvm.host.enable = true;

      # Load microVM host kernel modules at boot rather than relying on lazy
      # autoload at first VM start. Under lockdown=confidentiality
      # (modules/side-channel.nix) a post-boot module load is the fragile
      # case; loading them here surfaces any problem at boot instead of
      # silently failing to launch the workstation. All are in-tree (signed
      # with the kernel's build key); kvm pulls in its vendor submodule
      # (kvm-intel/kvm-amd) itself. The host GPU driver is hardware-specific
      # and loads via initrd/udev.
      boot.kernelModules = [ "kvm" "tun" "vhost" "vhost_net" ];

      # Backing directory for the workstation's persistent /home volume.
      # Lives on the host's LUKS-encrypted /persist so the guest's keys,
      # passwords and dev work survive reboots and are encrypted at rest.
      # 0700 root: only the (root-run) microVM service reaches the raw image.
      systemd.tmpfiles.rules = [
        "d /persist/microvms 0700 root root - -"
        "d /persist/microvms/workstation 0700 root root - -"
        # Source dir for the workstation's `ws-secrets` 9p share (login-hash
        # file written by the installer). 0755 so the share is readable
        # whether qemu runs as root or the unprivileged microvm user. The
        # directory sits on LUKS-encrypted /persist and holds only a
        # per-install password hash.
        "d /persist/ws-secrets 0755 root root - -"
      ];

      # Turn the Tor gateway into a transparent proxy for the internal network.
      anon.torGateway.internal = {
        enable = true;
        interface = "virbr-anon";
        address = "10.152.152.1";
      };

      # Isolated internal bridge, no uplink, static gateway address.
      systemd.network.netdevs."10-virbr-anon".netdevConfig = {
        Kind = "bridge";
        Name = "virbr-anon";
      };
      systemd.network.networks."10-virbr-anon" = {
        matchConfig.Name = "virbr-anon";
        address = [ "10.152.152.1/24" ];
        networkConfig = {
          ConfigureWithoutCarrier = true;
          # Deliberately NO Gateway, NO uplink, NO IPMasquerade.
        };
        # The bridge stays carrier-less until the workstation tap attaches.
        # RequiredForOnline=no prevents systemd-networkd-wait-online from
        # blocking network-online.target (and thus wg-quick and Tor). The
        # static address is still assigned early, before Tor binds
        # ${config.anon.torGateway.internal.address}.
        linkConfig.RequiredForOnline = "no";
      };

      # The workstation's tap joins the isolated bridge (and nothing else).
      systemd.network.networks."20-ws-tap" = {
        matchConfig.Name = "vm-anon-ws";
        networkConfig.Bridge = "virbr-anon";
        linkConfig.RequiredForOnline = "no";
      };

      ######################################################################
      # Workstation microVM definition.
      ######################################################################
      microvm.vms.workstation = {
        config = {
          imports = [ ./workstation.nix ];
          # Forward host-level toggles into the guest system so they can be
          # driven from hosts/anon/default.nix (see option declarations above).
          anon.workstation.desktop.enable = cfg.desktop.enable;
          anon.workstation.toolkit.enable = cfg.toolkit.enable;
          anon.workstation.crypto.enable = cfg.crypto.enable;
        };
      };
    })
  ];
}
