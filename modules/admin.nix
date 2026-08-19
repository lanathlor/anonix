##############################################################################
# Admin-access policy: immutable users, locked root, doas instead of sudo.
#
# Imported by both hosts/anon/default.nix and tests/security.nix. The test
# asserts these exact properties (no sudo, root locked, doas wheel-only, no
# passwordless escalation), so a regression here fails CI instead of shipping.
##############################################################################
{ lib, config, ... }:

{
  # Immutable users: account definitions live entirely in the store, so a
  # wiped (tmpfs) root still boots with a working login.
  #
  # The password is not in the Nix store: it is read at activation from a hash
  # file on the (LUKS-encrypted) /persist volume. Create it once on the target
  # before the first switch, or the account will be locked:
  #
  #   umask 077
  #   mkpasswd -m sha-512 | doas tee /persist/secrets/anon.passwd
  #
  # /persist is neededForBoot, so it is mounted before this file is read.
  users.mutableUsers = false;
  users.users.anon = {
    isNormalUser = true;
    description = "anon";
    extraGroups = [ "wheel" ];
    hashedPasswordFile = "/persist/secrets/anon.passwd";
  };

  # Lock root (no usable password hash). Guarded so we set "!" only when
  # nothing else already gives root a password file. In NixOS VM tests,
  # test-instrumentation.nix sets root's hashedPasswordFile for console login;
  # adding "!" on top would trip an eval warning and be overridden anyway.
  # On the real host nothing sets a file, so root is locked as intended
  # (tests/invariants.nix asserts this).
  users.users.root.hashedPassword =
    lib.mkIf (config.users.users.root.hashedPasswordFile == null) "!";

  # doas instead of sudo: smaller, more auditable SUID binary. `wheel`
  # escalates with a password (cached briefly like sudo's timestamp).
  # Run admin commands as `doas <cmd>` (e.g. `doas nixos-rebuild`).
  security.sudo.enable = false;
  security.doas = {
    enable = true;
    # Do not set keepEnv = true: it would carry the caller's PATH/LD_PRELOAD
    # into the root command, defeating the purpose of a hardened doas.
    extraRules = [{ groups = [ "wheel" ]; persist = true; }];
  };
}
