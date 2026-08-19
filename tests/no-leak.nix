##############################################################################
# QEMU VM test: with the VPN tunnel up, nothing leaks to the clearnet wire.
#
# The `vpn` node acts as the WireGuard endpoint and the capture point. The
# gateway establishes a real handshake (tunnel-up state, complement of the
# fail-closed test). We packet-capture the gateway's WAN link while it actively
# tries to talk (TCP, DNS, ICMP) and assert every IP packet is encrypted
# WireGuard. No plaintext DNS, no TCP SYN to :80/:443, no ICMP.
#
# Limit: proves nothing leaks past the tunnel. It does not prove tunnel contents
# are a working Tor circuit; Tor needs a directory consensus (requires chutney,
# out of scope). What enters the tunnel is the gateway's Tor daemon, as expected.
#
# Test-only WireGuard keypairs are embedded (throwaway, not secret).
#
# Run: `nix build .#checks.x86_64-linux.no-clearnet-leak -L` (or `just test-leak`).
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
  name = "no-clearnet-leak";

  nodes = {
    # The fake VPN endpoint: a WireGuard server and the WAN wire we capture.
    vpn = { pkgs, ... }: {
      networking.firewall.enable = false;
      environment.systemPackages = [ pkgs.tcpdump ];
      networking.wireguard.interfaces.wg0 = {
        ips = [ "${srvTunIp}/24" ];
        listenPort = wgPort;
        privateKey = srvPriv;
        peers = [{
          publicKey = gwPub;
          allowedIPs = [ "${gwTunIp}/32" ];
        }];
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

      # Point the real VPN config at our fake endpoint so the tunnel comes up.
      anon.vpn.endpointIp = nodes.vpn.networking.primaryIPAddress;
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
    vpn.wait_for_unit("multi-user.target")
    gateway.wait_for_unit("multi-user.target")
    vpn.wait_for_unit("wireguard-wg0.service")

    with subtest("the VPN WireGuard tunnel actually comes up"):
        # wait for a completed handshake (latest-handshakes timestamp != 0).
        gateway.wait_until_succeeds(
            "wg show wg-tunnel latest-handshakes | awk '{print $2}' | grep -qxv 0",
            timeout=90,
        )

    gwip = gateway.succeed(
        "ip -4 -o addr show eth1 | awk '{print $4}' | cut -d/ -f1"
    ).strip()

    with subtest("only encrypted WireGuard leaves the gateway (no clearnet leak)"):
        # Capture every IP packet from the gateway on the WAN wire.
        vpn.succeed(
            f"tcpdump -i eth1 -n -w /tmp/cap.pcap 'ip and host {gwip}' >/dev/null 2>&1 &"
        )
        vpn.sleep(2)

        # Make the gateway try to talk clearnet: TCP, DNS, ICMP.
        # All must be forced into Tor or dropped; none may appear as cleartext.
        gateway.execute("timeout 4 curl -s http://1.2.3.4/ || true")
        gateway.execute("timeout 4 curl -s https://1.2.3.4/ || true")
        gateway.execute("ping -c2 -W1 1.2.3.4 || true")
        gateway.execute("timeout 4 dig +tries=1 +time=1 @1.2.3.4 example.com || true")
        gateway.sleep(3)

        vpn.succeed("pkill -INT tcpdump || true")
        vpn.sleep(1)

        # Sanity: we captured WireGuard, confirming the wire was exercised.
        wg_pkts = int(vpn.succeed(
            f"tcpdump -nr /tmp/cap.pcap 'udp port ${toString wgPort} and src {gwip}' 2>/dev/null | wc -l"
        ).strip())
        assert wg_pkts > 0, "no WireGuard packets captured; tunnel was not exercised"

        # Assert nothing from the gateway that is not WireGuard.
        leak = vpn.succeed(
            f"tcpdump -nr /tmp/cap.pcap 'ip and src {gwip} and not (udp port ${toString wgPort})' 2>/dev/null || true"
        ).strip()
        assert leak == "", f"CLEARNET LEAK: non-WireGuard egress from gateway:\n{leak}"

        # Belt-and-suspenders: no plaintext DNS, HTTP, HTTPS, or ICMP.
        for bad, what in [
            (f"src {gwip} and udp port 53", "plaintext DNS"),
            (f"src {gwip} and tcp port 80", "clearnet HTTP"),
            (f"src {gwip} and tcp port 443", "clearnet HTTPS"),
            (f"src {gwip} and icmp", "ICMP"),
        ]:
            n = int(vpn.succeed(
                f"tcpdump -nr /tmp/cap.pcap '{bad}' 2>/dev/null | wc -l"
            ).strip())
            assert n == 0, f"leak: saw {n} {what} packets on the clearnet wire"
  '';
}
