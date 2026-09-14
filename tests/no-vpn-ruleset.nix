##############################################################################
# Fast, eval-level check for direct-Tor mode (anon.vpn.enable = false).
#
# Evaluates the gateway with the VPN transport off and asserts the killswitch
# re-pins correctly: every wg-tunnel reference is gone, the Tor daemon's own
# sockets are the permitted egress, and the fail-closed posture (default-drop
# on all chains, DNS via Tor's resolver) is unchanged. Requires no QEMU and
# no VPN values; tests/no-vpn-direct.nix proves the same mode in a booted VM.
#
# Build: `nix build .#checks.x86_64-linux.no-vpn-ruleset -L`.
##############################################################################
{ system, nixpkgs }:

let
  pkgs = nixpkgs.legacyPackages.${system};
  lib = nixpkgs.lib;

  gw = nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      ../modules/tor-gateway.nix
      ../modules/vpn.nix
      {
        nixpkgs.hostPlatform = system;
        anon.vpn.enable = false;
        # No other anon.vpn.* value is set: direct mode must evaluate with
        # the placeholders untouched (their assertions are gated off).
      }
    ];
  };

  c = gw.config;
  ruleset = c.networking.nftables.ruleset;
  torUid = toString c.users.users.tor.uid;

  count = needle: hay: builtins.length (lib.splitString needle hay) - 1;

  checks = [
    { name = "no wg-tunnel reference survives in the ruleset";
      ok = !lib.hasInfix "wg-tunnel" ruleset; }
    { name = "no placeholder value leaks into the ruleset";
      ok = !lib.hasInfix "PLACEHOLDER" ruleset; }
    { name = "Tor's own sockets are the permitted egress (uid pin, no interface pin)";
      ok = lib.hasInfix "meta skuid ${torUid} accept" ruleset; }
    { name = "input, forward and output chains still default-drop";
      ok = count "policy drop" ruleset >= 3; }
    { name = "app TCP and DNS are still redirected into Tor";
      ok = lib.hasInfix "redirect to :9040" ruleset
        && lib.hasInfix "redirect to :9053" ruleset; }
    { name = "no WireGuard interface is configured";
      ok = c.networking.wg-quick.interfaces == { }; }
    { name = "tor does not wait for the (absent) tunnel unit";
      ok = !lib.elem "wg-quick-wg-tunnel.service" c.systemd.services.tor.after; }
    { name = "DNS still points at Tor's resolver on loopback";
      ok = c.networking.nameservers == [ "127.0.0.1" ]; }
    { name = "the posture change is surfaced as a build-time warning";
      ok = lib.any (w: lib.hasInfix "anon.vpn.enable is false" w) c.warnings; }
  ];

  failed = lib.filter (x: !x.ok) checks;
  report = lib.concatMapStringsSep "\n"
    (x: "  ${if x.ok then "PASS" else "FAIL"}  ${x.name}") checks;
in
pkgs.runCommand "no-vpn-ruleset"
  {
    inherit report;
    passed = toString (builtins.length checks - builtins.length failed);
    total = toString (builtins.length checks);
  } ''
  printf 'direct-Tor (no-VPN) killswitch invariants (%s/%s passed):\n%s\n' \
    "$passed" "$total" "$report"
  touch "$out"
  ${lib.optionalString (failed != [ ]) ''
    printf '\nDIRECT-TOR INVARIANTS FAILED (see FAIL lines above).\n' >&2
    exit 1
  ''}
''
