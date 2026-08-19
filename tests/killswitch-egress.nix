##############################################################################
# QEMU VM test: the killswitch stays fail-closed when a single component dies.
#
# Starts from a healthy state (real WireGuard tunnel to a fake VPN endpoint,
# same setup as tests/no-leak.nix), then kills one component at a time:
#
#   * Kill only Tor: apps' TCP is NAT-redirected to Tor's dead port, dies at
#     loopback (RST), never reaches the wire. DNS and ICMP dropped. No clearnet.
#   * Kill only the VPN: wg-tunnel disappears, Tor's egress no longer matches
#     the oifname pin and is dropped. No WireGuard leaves either.
#
# The `wan` node is both the WireGuard endpoint and the capture point.
# Test-only WireGuard keypairs are embedded (throwaway), matching no-leak.nix.
#
# NOTE: needs KVM (`nix build .#checks.x86_64-linux.killswitch-egress -L`).
##############################################################################
{ system, nixpkgs }:

let
  pkgs = nixpkgs.legacyPackages.${system};

  srvPriv = "oPS+AWeNc6h86hh3HYYVUAFS16I/UA6HIFfbm8WQUkA=";
  srvPub = "5nUowTsNrs/43FrpflIaXy/vQ+aWtRAwfBJIBVFCxmk=";
  gwPriv = "wEm+ts3fxsUrbF857rbOg48aJjGrMzHuZWhjN0vzslE=";
  gwPub = "rf/fmAm/2F6bOd9hNxyHShdFYhk+OLrrZAuHjf8Sd2k=";

  wgPort = 51820;
  srvTunIp = "10.66.66.1";
  gwTunIp = "10.66.66.2";
in
pkgs.testers.runNixOSTest {
  name = "killswitch-egress";

  nodes = {
    # The fake VPN endpoint + the WAN wire we capture.
    wan = { pkgs, ... }: {
      networking.firewall.enable = false;
      environment.systemPackages = [ pkgs.tcpdump ];
      networking.wireguard.interfaces.wg0 = {
        ips = [ "${srvTunIp}/24" ];
        listenPort = wgPort;
        privateKey = srvPriv;
        peers = [{ publicKey = gwPub; allowedIPs = [ "${gwTunIp}/32" ]; }];
      };
    };

    gateway = { config, pkgs, lib, nodes, ... }: {
      imports = [
        ../modules/tor-gateway.nix
        ../modules/vpn.nix
        ../modules/hardening.nix
        ../modules/admin.nix
        ../modules/updates.nix
      ];

      # Real handshake to the fake endpoint so the tunnel genuinely comes UP.
      anon.vpn.endpointIp = nodes.wan.networking.primaryIPAddress;
      anon.vpn.endpointPort = wgPort;
      anon.vpn.serverPublicKey = srvPub;
      anon.vpn.interfaceAddress = [ "${gwTunIp}/32" ];
      anon.vpn.privateKeyFile = lib.mkForce (toString (pkgs.writeText "gw-wg.key" gwPriv));

      users.users.anon.hashedPasswordFile = lib.mkForce null;
      systemd.network.wait-online.enable = lib.mkForce false;

      # Tools to generate would-be-leaking traffic.
      environment.systemPackages = with pkgs; [ curl dnsutils iputils ];
    };
  };

  testScript = ''
    start_all()
    wan.wait_for_unit("multi-user.target")
    gateway.wait_for_unit("multi-user.target")
    wan.wait_for_unit("wireguard-wg0.service")

    # Bring the tunnel UP (wait for a completed handshake), then learn the
    # gateway's WAN address on the wire.
    gateway.wait_until_succeeds(
        "wg show wg-tunnel latest-handshakes | awk '{print $2}' | grep -qxv 0",
        timeout=90,
    )
    gwip = gateway.succeed("ip -4 -o addr show eth1 | awk '{print $4}' | cut -d/ -f1").strip()

    def capture_egress(pcap, label):
        """Capture the gateway's egress while it tries to talk clearnet.
        Returns every non-WireGuard IP packet it emitted."""
        wan.succeed(f"rm -f {pcap}; tcpdump -i eth1 -n -w {pcap} 'ip and host {gwip}' >/dev/null 2>&1 &")
        wan.sleep(2)
        gateway.execute("timeout 4 curl -s http://1.2.3.4/ || true")
        gateway.execute("timeout 4 curl -s https://1.2.3.4/ || true")
        gateway.execute("timeout 4 dig +tries=1 +time=1 @1.2.3.4 example.com || true")
        gateway.execute("ping -c2 -W1 1.2.3.4 || true")
        gateway.sleep(3)
        wan.succeed("pkill -INT tcpdump || true")
        wan.sleep(1)
        leak = wan.succeed(
            f"tcpdump -nr {pcap} 'ip and src {gwip} and not (udp port ${toString wgPort})' 2>/dev/null || true"
        ).strip()
        return leak

    with subtest("baseline (healthy): only encrypted WireGuard leaves the wire"):
        leak = capture_egress("/tmp/base.pcap", "baseline")
        assert leak == "", f"baseline leak (non-WireGuard egress):\n{leak}"

    with subtest("kill only Tor -> fail-closed, no clearnet leak"):
        gateway.succeed("systemctl stop tor.service")
        leak = capture_egress("/tmp/tor.pcap", "tor-down")
        assert leak == "", f"LEAK after Tor was killed:\n{leak}"
        # The intended (torified) path is closed too: an app cannot get out.
        gateway.fail("timeout 6 curl -s http://1.2.3.4/")
        gateway.succeed("systemctl start tor.service")

    with subtest("kill only the VPN -> fail-closed, no clearnet leak"):
        gateway.succeed("systemctl stop wg-quick-wg-tunnel.service")
        # Tunnel is genuinely gone (not merely idle).
        gateway.fail("ip link show wg-tunnel")
        # With the tunnel down, Tor's egress no longer matches the oifname pin
        # and is dropped. Assert no non-WireGuard egress (the security property)
        # rather than strict zero packets, to avoid flakes on teardown traffic.
        leak = capture_egress("/tmp/vpn.pcap", "vpn-down")
        assert leak == "", f"CLEARNET LEAK after VPN was killed:\n{leak}"
        # Egress tripwire must have logged the drops.
        gateway.wait_until_succeeds("journalctl -k --no-pager | grep -q KILLSWITCH-DROP-OUT", timeout=15)
  '';
}
