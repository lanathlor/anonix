##############################################################################
# Persist-provisioning script, shared by modules/persist-provision.nix and
# tests/duress.nix. Repopulates the minimum a wiped/fresh /persist needs.
##############################################################################
{
  pkgs,
  lib,
  decoyHash,
}:

let
  # The fallback login hash as an on-disk file we can `install` from.
  decoyFile = pkgs.writeText "decoy.passwd" (decoyHash + "\n");
in
pkgs.writeShellScript "persist-provision" ''
  # Runs before the `users`/`etc` steps; name resolution is not available yet.
  # Use numeric 0:0, not `root`, or install/chown fail with "invalid user 'root'".
  install -d -m 0700 -o 0 -g 0 /persist/secrets
  install -d -m 0755 -o 0 -g 0 /persist/ws-secrets
  install -d -m 0700 -o 0 -g 0 /persist/microvms /persist/microvms/workstation
  install -d -m 0700 -o 0 -g 0 /persist/secureboot

  # Login hash must be present before `users` writes /etc/shadow or the
  # immutable account locks. A duress boot seeds it from the typed passphrase;
  # on a fresh /persist fall back to the baked decoy so login never locks.
  if [ ! -s /persist/secrets/anon.passwd ]; then
    install -m 0400 -o 0 -g 0 ${decoyFile} /persist/secrets/anon.passwd
  fi
  if [ ! -s /persist/ws-secrets/user.passwd ]; then
    install -m 0644 -o 0 -g 0 ${decoyFile} /persist/ws-secrets/user.passwd
  fi

  # Ensure agenix has a readable identity. A freshly generated identity cannot
  # decrypt secrets sealed to the old key; the tolerant age wrapper then yields
  # an empty secret and the killswitch keeps the box offline (correct for a decoy).
  if [ ! -s /persist/secrets/age-identity ]; then
    ( umask 077; ${pkgs.age}/bin/age-keygen -o /persist/secrets/age-identity 2>/dev/null ) \
      || echo "[persist-provision] WARNING: age-keygen failed" >&2
    chmod 0400 /persist/secrets/age-identity 2>/dev/null || :
    chown 0:0 /persist/secrets/age-identity 2>/dev/null || :
  fi
''
