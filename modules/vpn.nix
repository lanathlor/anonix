##############################################################################
# The VPN transport: a raw WireGuard full tunnel (no mutable daemon state).
#
# This tunnel is the transport that carries Tor traffic. It becomes the
# machine's default route; Tor's connections to its guards travel through it,
# so your ISP sees only WireGuard to your VPN endpoint, never Tor and never
# clearnet.
#
# Provider-agnostic: any WireGuard endpoint works (Mullvad, IVPN, ProtonVPN,
# AzireVPN, or a WireGuard server you host yourself). This is deliberately
# WireGuard-only — a kernel-level named interface is what lets the killswitch
# pin egress with a single nftables rule, with no mutable daemon state to
# reason about. An OpenVPN/`tun` + proprietary-daemon path would reintroduce
# exactly the state and process-egress complexity this design closes off, so
# it is out of scope.
#
# How to fill this in
# -------------------
# 1. Get a WireGuard configuration from your provider (a generated `.conf`
#    gives every value below). Mullvad example: log in at
#    https://mullvad.net -> Account -> WireGuard configuration.
# 2. Encrypt the private key with agenix (never touches git in plaintext):
#       cd secrets && nix run ..#agenix -- -e vpn-wg.key.age
#    See modules/secrets.nix and secrets/secrets.nix.
# 3. Fill the non-secret values (address, endpoint, peer public key) below.
##############################################################################
{ config, lib, pkgs, ... }:

let
  cfg = config.anon.vpn;
in {
  options.anon.vpn = {
    endpointIp = lib.mkOption {
      type = lib.types.str;
      default = "PLACEHOLDER_ENDPOINT_IP"; # e.g. "193.138.7.100"
      description = "Public IPv4 of the chosen WireGuard server.";
    };
    endpointPort = lib.mkOption {
      type = lib.types.port;
      default = 51820;
      description = "WireGuard UDP port (usually 51820).";
    };
    serverPublicKey = lib.mkOption {
      type = lib.types.str;
      default = "PLACEHOLDER_SERVER_PUBLIC_KEY=";
      description = "The [Peer] PublicKey from the WireGuard config.";
    };
    interfaceAddress = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "10.64.0.2/32" ]; # PLACEHOLDER: the [Interface] Address.
      description = "The provider-assigned address for this device.";
    };
    privateKeyFile = lib.mkOption {
      type = lib.types.str;
      # Decrypted by agenix at boot to /run/agenix/vpn-wg (tmpfs, root-only).
      default = config.age.secrets."vpn-wg".path;
      defaultText = lib.literalExpression ''config.age.secrets."vpn-wg".path'';
      description = "Path to the (agenix-decrypted) WireGuard private key.";
    };
  };

  config = {
    # wg-quick (not the plain wireguard module) correctly handles a 0.0.0.0/0
    # full tunnel: it uses fwmark + policy routing so the encrypted packets to
    # the endpoint don't loop back into the tunnel.
    networking.wg-quick.interfaces.wg-tunnel = {
      address = cfg.interfaceAddress;
      privateKeyFile = cfg.privateKeyFile;

      # Do NOT use the provider's DNS. All DNS goes through Tor's DNSPort (see
      # tor-gateway.nix), so we leave resolv.conf pointing at loopback.
      # dns = [ ];

      peers = [{
        publicKey = cfg.serverPublicKey;
        endpoint = "${cfg.endpointIp}:${toString cfg.endpointPort}";
        # Route everything into the tunnel. IPv6 is disabled system-wide, so
        # only the v4 default route is added here.
        allowedIPs = [ "0.0.0.0/0" ];
        persistentKeepalive = 25;
      }];
    };

    # Resolver points at loopback; Tor's DNSPort answers (see tor-gateway.nix).
    networking.nameservers = lib.mkForce [ "127.0.0.1" ];
    services.resolved.enable = false;
    networking.dhcpcd.extraConfig = "nohook resolv.conf";

    # Fail the build if the peer public key was never filled in. Without it
    # the tunnel silently never comes up (killswitch keeps the box offline,
    # safe but hard to diagnose). endpointIp is asserted in tor-gateway.nix.
    # interfaceAddress is left unasserted: its default is a usable value, not
    # a sentinel string.
    assertions = [{
      assertion = cfg.serverPublicKey != "PLACEHOLDER_SERVER_PUBLIC_KEY=";
      message = ''
        anon.vpn.serverPublicKey is still the placeholder. Fill in the
        [Peer] PublicKey from your WireGuard config in modules/vpn.nix
        before deploying to hardware.
      '';
    }];
  };
}
