##############################################################################
# QEMU VM test: the gateway must not drop return traffic to the workstation.
#
# Regression test for the isolated-workstation path. With
# anon.torGateway.internal.enable set, the workstation's TCP is REDIRECTed into
# the gateway's Tor (TransPort/DNSPort bound on the internal address). The
# gateway's replies are locally generated and egress the internal interface, so
# the killswitch output chain must permit them. The original ruleset pinned every
# stateful accept to oifname "wg-tunnel", so replies hit the default-drop policy
# and the workstation could never complete the TCP handshake to Tor. This test
# reproduces that: a node on the internal LAN must be able to reach the gateway's
# Tor TransPort, which requires the gateway's SYN-ACK to be allowed out.
#
# Uses eth1 as the internal interface, mirroring how the real host wires
# virbr-anon. The tunnel is intentionally left down (no key) so the killswitch
# stays fail-closed; the return-traffic path is independent of the tunnel.
#
# NOTE: needs KVM (`nix build .#checks.x86_64-linux.workstation-return -L`).
##############################################################################
{ system, nixpkgs }:

let
  pkgs = nixpkgs.legacyPackages.${system};
in
pkgs.testers.runNixOSTest {
  name = "workstation-return";

  nodes = {
    # Stands in for the isolated workstation microVM: plain host on eth1.
    # Its traffic to the gateway is what the gateway redirects into Tor.
    workstation = { pkgs, ... }: {
      networking.firewall.enable = false;
      environment.systemPackages = [ pkgs.netcat-openbsd ];
    };

    gateway = { config, pkgs, lib, ... }: {
      imports = [
        ../modules/tor-gateway.nix
        ../modules/vpn.nix
        ../modules/hardening.nix
        ../modules/admin.nix
        ../modules/updates.nix
      ];

      # Dummy VPN values: pass the placeholder assertions; no key so the
      # tunnel never comes up. The return-traffic path is independent of it.
      anon.vpn.endpointIp = "192.0.2.1";
      anon.vpn.serverPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      anon.vpn.privateKeyFile = lib.mkForce "/etc/vpn-key-absent";

      # Treat eth1 as the internal network, mirroring virbr-anon in microvm-host.nix.
      anon.torGateway.internal = {
        enable = true;
        interface = "eth1";
        address = config.networking.primaryIPAddress;
      };

      users.users.anon.hashedPasswordFile = lib.mkForce null;
      systemd.network.wait-online.enable = lib.mkForce false;
    };
  };

  testScript = ''
    start_all()
    gateway.wait_for_unit("multi-user.target")
    workstation.wait_for_unit("multi-user.target")

    gw_ip = gateway.succeed(
        "ip -4 -o addr show eth1 | awk '{print $4}' | cut -d/ -f1"
    ).strip()
    ws_ip = workstation.succeed(
        "ip -4 -o addr show eth1 | awk '{print $4}' | cut -d/ -f1"
    ).strip()

    with subtest("the gateway's Tor transparent-proxy port is listening"):
        gateway.wait_for_unit("tor.service")
        # Wait until the TransPort socket is open before probing from the workstation.
        gateway.wait_until_succeeds(f"ss -ltn | grep -q '{gw_ip}:9040'", timeout=60)

    with subtest("workstation can reach Tor (gateway return traffic is not dropped)"):
        # The workstation's SYN is redirected into Tor on the gateway. Completing
        # the handshake requires the gateway's SYN-ACK to leave the internal
        # interface. With the bug, the output policy discards it and this times
        # out. With the fix, the handshake completes.
        workstation.succeed(f"nc -z -w 8 {gw_ip} 9040")

    with subtest("no killswitch drop was logged for a reply to the workstation"):
        # Must be scoped to the workstation's address. The tunnel is down, so the
        # gateway legitimately logs KILLSWITCH-DROP-OUT for its own Tor bootstrap
        # (OUT=<wan nic>, the killswitch working correctly). A return-traffic
        # regression shows OUT=<internal iface> with DST=<ws ip>, so we only
        # fail on drops whose destination is the workstation.
        gateway.fail(
            f"journalctl -k --no-pager | grep KILLSWITCH-DROP-OUT | grep -q 'DST={ws_ip}'"
        )
  '';
}
