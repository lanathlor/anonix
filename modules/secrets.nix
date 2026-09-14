##############################################################################
# agenix wiring.
#
# Secrets are age-encrypted (see ../secrets/) and committed to git. At
# activation, agenix decrypts them to /run/agenix/<name> (tmpfs). The
# decryption identity lives on /persist, which is neededForBoot and therefore
# mounted before the agenix activation step.
##############################################################################
{ config, lib, ... }:

{
  # Machine's private age identity. Generate once on the target:
  #   sudo install -d -m 0700 /persist/secrets
  #   sudo age-keygen -o /persist/secrets/age-identity
  # Put the printed public key into ../secrets/secrets.nix and re-encrypt.
  age.identityPaths = [ "/persist/secrets/age-identity" ];

  # Only declared while the VPN transport is on: with anon.vpn.enable = false
  # there is no key to decrypt, and agenix would otherwise fail activation on
  # a placeholder/absent secret. (`or true` keeps this module usable where
  # vpn.nix is not imported.)
  age.secrets."vpn-wg" = lib.mkIf (config.anon.vpn.enable or true) {
    file = ../secrets/vpn-wg.key.age;
    # Decrypted to /run/agenix/vpn-wg (root-only); wg-quick runs as root.
    mode = "0400";
    owner = "root";
    group = "root";
  };
}
