##############################################################################
# QEMU VM test for the gateway's security posture, exercised offline.
#
# Cannot prove traffic exits via Tor end-to-end (needs live network, out of
# scope). Does prove: the killswitch is fail-closed (tunnel down, nothing
# egresses), the nftables ruleset matches the design, IPv6 is off, and the
# privilege-escalation and hardening posture holds.
#
# Imports the real modules with dummy VPN values and no key, so the tunnel
# never comes up. A bare `peer` node on the same LAN shows that traffic that
# would otherwise be deliverable is dropped.
#
# Run: `nix build .#checks.x86_64-linux.gateway-security -L` (or `just test-sec`).
##############################################################################
{ system, nixpkgs }:

let
  pkgs = nixpkgs.legacyPackages.${system};
in
pkgs.testers.runNixOSTest {
  name = "gateway-security";

  nodes = {
    # A plain reachable host on the test LAN (the "would otherwise work" target).
    peer = { ... }: {
      networking.firewall.enable = false;
    };

    gateway = { config, pkgs, lib, ... }: {
      imports = [
        ../modules/tor-gateway.nix
        ../modules/vpn.nix
        ../modules/hardening.nix
        ../modules/admin.nix
        ../modules/updates.nix
      ];

      # Dummy VPN values: pass the placeholder assertions; no private key so
      # the tunnel never comes up. This is the fail-closed state under test.
      anon.vpn.endpointIp = "192.0.2.1";
      anon.vpn.serverPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      anon.vpn.privateKeyFile = lib.mkForce "/etc/vpn-key-absent";

      # A non-wheel user, to prove doas denies non-admins outright.
      users.users.nonadmin.isNormalUser = true;
      # No /persist in the test; anon login works without a hash file.
      users.users.anon.hashedPasswordFile = lib.mkForce null;

      # The killswitch blocks all egress, so wait-online would stall forever.
      systemd.network.wait-online.enable = lib.mkForce false;
    };
  };

  testScript = ''
    start_all()
    gateway.wait_for_unit("multi-user.target")
    peer.wait_for_unit("multi-user.target")

    with subtest("killswitch ruleset is present and default-drop"):
        rules = gateway.succeed("nft list ruleset")
        assert "table ip tor_nat" in rules, "missing Tor NAT table"
        assert "table inet tor_fw" in rules, "missing killswitch filter table"
        assert "redirect to :9040" in rules, "app TCP is not redirected into Tor"
        assert "redirect to :9053" in rules, "DNS is not redirected into Tor"
        assert 'oifname "wg-tunnel"' in rules, "egress is not pinned to the tunnel"
        assert "skuid" in rules, "Tor uid rule missing"
        # input, forward and output hooks all default to drop.
        assert rules.count("policy drop") >= 3, "not all chains default-drop"

    with subtest("fail-closed: nothing egresses while the tunnel is down"):
        # ICMP to a directly-connected peer is not NAT-redirected; it hits the
        # output policy and is dropped. A would-be-deliverable packet is blocked.
        gateway.fail("ping -c1 -W2 peer")
        # ... and the egress tripwire logged it, proving nftables did the drop.
        gateway.wait_until_succeeds(
            "journalctl -k --no-pager | grep -q KILLSWITCH-DROP-OUT", timeout=15
        )

    with subtest("no IPv6 anywhere"):
        assert gateway.succeed("cat /proc/sys/net/ipv6/conf/all/disable_ipv6").strip() == "1"
        gateway.fail("ip -6 addr show scope global | grep -q inet6")

    with subtest("privilege escalation is locked down"):
        # sudo is not installed at all.
        gateway.fail("command -v sudo")
        # doas is present and SUID root.
        doas = gateway.succeed("command -v doas").strip()
        gateway.succeed(f"test -u {doas}")
        # Root-lock is asserted in checks.anon-security-invariants; the nixosTest
        # framework force-unlocks root for console access, so it is not observable
        # inside a test VM.
        # Wheel may escalate only with a password. The only nopass rule permitted
        # is the NixOS default for root itself (not an escalation); assert no
        # nopass rule for any non-root principal such as :wheel.
        gateway.succeed("grep -Eq 'permit.*:wheel' /etc/doas.conf")
        gateway.fail("grep nopass /etc/doas.conf | grep -vq ' root'")
        # A non-wheel user cannot escalate via doas at all.
        gateway.fail("su nonadmin -s /bin/sh -c 'doas -n true'")

    with subtest("hardening sysctls are applied"):
        def sysctl(k):
            return gateway.succeed(f"cat /proc/sys/{k}").strip()
        assert sysctl("kernel/kptr_restrict") == "2"
        assert sysctl("kernel/yama/ptrace_scope") == "2"
        assert sysctl("kernel/unprivileged_bpf_disabled") == "1"
        assert sysctl("kernel/dmesg_restrict") == "1"

    with subtest("forensic-hygiene + sealed-appliance defaults"):
        # No unproxied time sync.
        gateway.fail("systemctl is-enabled systemd-timesyncd.service")
        # Volatile journald => no on-disk journal directory.
        gateway.fail("test -d /var/log/journal")
        # Sealed appliance: public binary cache must not be a configured substituter.
        # Anchor to the substituters line to avoid matching the trusted-public-keys
        # entry, which legitimately names "cache.nixos.org-1".
        gateway.fail("grep -E '^(extra-)?substituters' /etc/nix/nix.conf | grep -q cache.nixos.org")
  '';
}
