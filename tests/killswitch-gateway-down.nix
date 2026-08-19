##############################################################################
# QEMU VM test: killing the gateway cuts the workstation off entirely.
#
# The workstation's only next hop is the gateway (single interface, no other
# routes). When the gateway dies, the workstation has nowhere to send packets.
# A leak is not just firewalled off; it is topologically impossible.
#
# We prove this via the workstation's lifeline: it can reach the gateway's Tor
# while the gateway is up, and cannot once the gateway is killed.
#
# Why not assert "can't reach a WAN host": every TCP connect from the workstation
# is transparently REDIRECTed into Tor, so nc -z completes the handshake at the
# Tor proxy regardless of destination. The crisp observable property is loss of
# the lifeline when the gateway dies.
#
# NOTE: needs KVM (`nix build .#checks.x86_64-linux.killswitch-gateway-down -L`).
##############################################################################
{ system, nixpkgs }:

let
  pkgs = nixpkgs.legacyPackages.${system};
in
pkgs.testers.runNixOSTest {
  name = "killswitch-gateway-down";

  nodes = {
    gateway = { config, pkgs, lib, ... }: {
      imports = [
        ../modules/tor-gateway.nix
        ../modules/vpn.nix
        ../modules/hardening.nix
        ../modules/admin.nix
        ../modules/updates.nix
      ];

      # Dummy VPN values; tunnel stays down. The internal network is the path under test.
      anon.vpn.endpointIp = "192.0.2.1";
      anon.vpn.serverPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      anon.vpn.privateKeyFile = lib.mkForce "/etc/vpn-key-absent";

      anon.torGateway.internal = {
        enable = true;
        interface = "eth1";
        address = config.networking.primaryIPAddress; # gateway's internal IP
      };

      users.users.anon.hashedPasswordFile = lib.mkForce null;
      systemd.network.wait-online.enable = lib.mkForce false;
    };

    # The isolated workstation: one interface, on the internal LAN only.
    workstation = { pkgs, ... }: {
      networking.firewall.enable = false;
      environment.systemPackages = [ pkgs.netcat-openbsd ];
    };
  };

  testScript = ''
    start_all()
    gateway.wait_for_unit("multi-user.target")
    workstation.wait_for_unit("multi-user.target")

    gwip = gateway.succeed("ip -4 -o addr show eth1 | awk '{print $4}' | cut -d/ -f1").strip()

    with subtest("gateway UP: the workstation's lifeline (the gateway's Tor) works"):
        gateway.wait_for_unit("tor.service")
        gateway.wait_until_succeeds(f"ss -ltn | grep -q '{gwip}:9040'", timeout=60)
        workstation.succeed(f"nc -z -w 8 {gwip} 9040")

    with subtest("gateway KILLED: the workstation is cut off, no fallback path"):
        gateway.crash()  # abrupt power-off; gateway.shutdown() also works
        # The only destination the workstation had is gone.
        workstation.fail(f"nc -z -w 6 {gwip} 9040")
  '';
}
