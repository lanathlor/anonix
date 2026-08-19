##############################################################################
# Persist provisioning.
#
# Root is tmpfs; everything durable lives on /persist. This module guarantees a
# wiped or brand-new /persist still boots into a working system: it backs the
# duress decoy (modules/duress.nix) and prevents login lockout on fresh installs.
#
# Runs as an activation script before `agenixNewGeneration` and `users` (the
# only way to reliably order before those), and:
#   * creates the /persist directory skeleton,
#   * writes a fallback login hash if none exists (so the immutable `anon`
#     account never locks; a duress boot seeds the real typed hash first),
#   * generates a fresh age identity if none exists.
#
# When duress is enabled, also wraps agenix's `age` so a failed decrypt yields
# an empty secret instead of aborting activation. An empty VPN key means
# the tunnel never comes up and the killswitch keeps the box offline, the
# correct safe state for a wiped decoy.
##############################################################################
{
  config,
  lib,
  pkgs,
  options,
  ...
}:

let
  cfg = config.anon.provision;

  provisionScript = import ./persist-provision-script.nix {
    inherit pkgs lib;
    decoyHash = cfg.decoyPasswordHash;
  };

  # Wire age-specific bits only when agenix is present (e.g. not in the VM test).
  ageDeclared = options ? age;
  duressOn = config.anon.duress.enable or false;

  # Drop-in for agenix's `age` that emits an empty output on decrypt failure
  # instead of aborting activation. agenix always invokes: age --decrypt -i ID... -o TMPFILE FILE.
  tolerantAge = pkgs.writeShellScript "age-tolerant" ''
    out=
    prev=
    for a in "$@"; do
      if [ "$prev" = "-o" ]; then out=$a; fi
      prev=$a
    done
    if ${pkgs.age}/bin/age "$@"; then
      exit 0
    fi
    echo "[agenix] decrypt failed; writing empty secret (duress/fresh identity)." >&2
    [ -n "$out" ] && : > "$out"
    exit 0
  '';
in
{
  options.anon.provision = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Create the /persist skeleton, fallback login hash, and age identity at
        activation. Prevents login lockout on a wiped (duress) or new /persist.
      '';
    };

    decoyPasswordHash = lib.mkOption {
      type = lib.types.str;
      # sha-512 crypt of "changeme". Change this.
      default = "$6$4jNpQuPiFL1C8ZUL$uRY1DG3W13oxGjvZKQGN4NWG0XvEOaU4rLSoIfI248Oifm.5muI.QfLH8xHTeLT11mnLRlFPpXlomsbV9kPr.1";
      description = ''
        Last-resort SHA-512 hash written to /persist/secrets/anon.passwd and
        ws-secrets/user.passwd only when none exists. Default hashes "changeme";
        override it. Normally unused: install-anon writes the real hash, and a
        duress boot seeds the hash of the typed passphrase.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        system.activationScripts.persistProvision = {
          deps = [ "specialfs" ];
          text = "${provisionScript}";
        };
        # Login hash must be in place before `users` writes /etc/shadow.
        system.activationScripts.users.deps = [ "persistProvision" ];
      }
      (lib.optionalAttrs ageDeclared {
        # Identity must exist before agenix tries to use it.
        system.activationScripts.agenixNewGeneration.deps = [ "persistProvision" ];
        # Tolerate decrypt failure (fresh duress identity) so boot never aborts.
        age.ageBin = lib.mkIf duressOn (lib.mkForce "${tolerantAge}");
      })
    ]
  );
}
