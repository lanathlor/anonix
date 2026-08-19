##############################################################################
# Fast, eval-level regression guard for the workstation return-traffic drop.
#
# The bug lives in the rendered nftables ruleset, so it can be caught without
# booting a VM (no KVM, unlike tests/workstation-return.nix which proves it
# end-to-end). Evaluates the gateway with the internal network enabled and
# asserts the killswitch output filter chain permits return traffic on the
# internal interface. Without such a rule every stateful accept is pinned to
# oifname "wg-tunnel", so Tor's replies to the workstation hit the default-drop
# policy and the workstation receives nothing.
#
# Build: `nix build .#checks.x86_64-linux.workstation-return-ruleset -L`.
##############################################################################
{ system, nixpkgs }:

let
  pkgs = nixpkgs.legacyPackages.${system};

  iface = "vint0"; # a distinctive internal-interface name to grep for

  gw = nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      ../modules/tor-gateway.nix
      ../modules/vpn.nix
      {
        nixpkgs.hostPlatform = system;
        anon.vpn.endpointIp = "192.0.2.1";
        anon.vpn.serverPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        anon.torGateway.internal.enable = true;
        anon.torGateway.internal.interface = iface;
        anon.torGateway.internal.address = "10.152.152.1";
      }
    ];
  };

  ruleset = gw.config.networking.nftables.ruleset;
in
pkgs.runCommand "workstation-return-ruleset"
  {
    inherit ruleset iface;
    passAsFile = [ "ruleset" ];
  } ''
  # Isolate the filter output chain (2nd occurrence: 1st is in table ip tor_nat,
  # 2nd is in table inet tor_fw).
  out_chain=$(awk '/chain output \{/{n++} n==2{print} n==2 && /^        \}/{exit}' "$rulesetPath")

  printf '=== filter output chain ===\n%s\n===========================\n' "$out_chain"

  if printf '%s\n' "$out_chain" | grep -Eq "oifname \"$iface\".*accept"; then
    echo "PASS: output chain accepts return traffic on the internal interface ($iface)."
    touch "$out"
  else
    echo "FAIL: the killswitch output chain has NO accept for return traffic on" >&2
    echo "      the internal interface ($iface). Tor's replies to the workstation" >&2
    echo "      egress there and are dropped by the default-drop policy, so the" >&2
    echo "      isolated workstation can never receive anything." >&2
    exit 1
  fi
''
