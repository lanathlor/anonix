##############################################################################
# agenix rules file. Lists, for each encrypted secret, the public keys allowed
# to DECRYPT it. Run agenix from THIS directory so it finds this file:
#
#   cd secrets
#   nix run ..#agenix -- -e vpn-wg.key.age         # create/edit a secret
#   nix run ..#agenix -- -r                        # re-key after changing keys
#
# These are PUBLIC keys, safe to commit. The matching PRIVATE identity lives
# only on the target machine at /persist/secrets/age-identity (never in git).
##############################################################################
let
  # The target machine's age identity PUBLIC key. Generate the private
  # identity on the machine and read its public key:
  #
  #   sudo install -d -m 0700 /persist/secrets
  #   sudo age-keygen -o /persist/secrets/age-identity     # prints "Public key: age1..."
  #   sudo age-keygen -y /persist/secrets/age-identity     # re-print it later
  #
  host = "age1PLACEHOLDER_REPLACE_WITH_MACHINE_PUBLIC_KEY";

  # Your personal admin key(s), so you can edit secrets from your workstation.
  # An age key (age1...) or an SSH public key (ssh-ed25519 AAAA...) both work.
  admin = "age1PLACEHOLDER_REPLACE_WITH_YOUR_ADMIN_PUBLIC_KEY";

  # Everyone who may decrypt: the machine (at boot) + you (to edit).
  all = [ host admin ];
in {
  "vpn-wg.key.age".publicKeys = all;
}
