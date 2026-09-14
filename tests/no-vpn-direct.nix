##############################################################################
# QEMU VM test for direct-Tor mode (anon.vpn.enable = false).
#
# Boots the gateway with the VPN transport off and proves the re-pinned
# killswitch end-to-end against a plain peer on the test LAN:
#   * Tor starts without waiting for any tunnel unit,
#   * the ruleset carries no wg-tunnel reference,
#   * the Tor daemon's own sockets CAN egress directly (the permitted path),
#   * everything else is still dropped and logged (fail-closed).
#
# Complements tests/no-vpn-ruleset.nix (the eval-level twin, no KVM needed).
# Run: `nix build .#checks.x86_64-linux.no-vpn-direct -L`.
##############################################################################
{ system, nixpkgs }:

let
  pkgs = nixpkgs.legacyPackages.${system};
in
pkgs.testers.runNixOSTest {
  name = "no-vpn-direct";

  nodes = {
    # A plain reachable host serving HTTP: the target Tor's sockets may reach
    # directly, and everyone else must not.
    peer = { pkgs, ... }: {
      networking.firewall.enable = false;
      systemd.services.hello = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8000";
      };
    };

    gateway = { pkgs, ... }: {
      imports = [
        ../modules/tor-gateway.nix
        ../modules/vpn.nix
      ];

      # The mode under test. No other anon.vpn.* value is set: direct mode
      # must build with the placeholders untouched and no VPN key anywhere.
      anon.vpn.enable = false;

      environment.systemPackages = [ pkgs.curl ];
    };
  };

  testScript = ''
    start_all()
    gateway.wait_for_unit("multi-user.target")
    peer.wait_for_unit("hello.service")

    with subtest("tor runs and is not ordered after any tunnel unit"):
        gateway.wait_for_unit("tor.service")
        after = gateway.succeed("systemctl show tor.service -p After")
        assert "wg-quick" not in after, f"tor still waits for the tunnel: {after}"

    with subtest("killswitch ruleset is default-drop with the pin moved to Tor"):
        rules = gateway.succeed("nft list ruleset")
        assert "table ip tor_nat" in rules, "missing Tor NAT table"
        assert "table inet tor_fw" in rules, "missing killswitch filter table"
        assert "wg-tunnel" not in rules, "a wg-tunnel rule survived without the VPN"
        assert "skuid" in rules, "Tor uid egress rule missing"
        assert rules.count("policy drop") >= 3, "not all chains default-drop"

    with subtest("Tor's own sockets can egress directly (the permitted path)"):
        # The nat output chain skuid-returns Tor's uid, so this connection is
        # not redirected; the filter chain must then let it out unpinned.
        gateway.succeed("runuser -u tor -- curl -sf -m10 http://peer:8000/ >/dev/null")

    with subtest("fail-closed: everything that is not Tor is still dropped"):
        # ICMP is never NAT-redirected; it hits the output policy directly.
        gateway.fail("ping -c1 -W2 peer")
        # Non-Tor TCP is redirected into Tor, which has no working circuit in
        # this offline test net: the peer must never see a direct connection.
        gateway.fail("curl -sf -m5 http://peer:8000/ >/dev/null")
        # ... and the egress tripwire logged the drop.
        gateway.wait_until_succeeds(
            "journalctl -k --no-pager | grep -q KILLSWITCH-DROP-OUT", timeout=15
        )
  '';
}
