##############################################################################
# Impermanence: root is tmpfs (see hardware-configuration.nix), so on every
# boot the system starts from a clean slate rebuilt from the Nix store. Only
# the paths bind-mounted from /persist below survive a reboot.
#
# Persist as little as possible. Everything not listed here is gone on
# reboot. If a service breaks after a reboot because it lost state, add the
# smallest possible path here and consider whether that state is an anonymity
# risk first.
#
# For Tails-style full amnesia: remove the /var/lib/tor entry (fresh entry
# guards every boot) and the machine-id file (fresh identity every boot).
# The Tor Project recommends stable entry guards, which is why guard state
# is persisted by default.
##############################################################################
{ config, lib, pkgs, ... }:

{
  # /persist itself must not be wiped; it is a real partition on hardware.
  # (Backed by tmpfs only inside the test VM, see hosts/anon/default.nix.)

  environment.persistence."/persist" = {
    hideMounts = true;

    directories = [
      # UID/GID allocation map: keep it so immutable users stay consistent.
      "/var/lib/nixos"

      # Persist Tor's DataDirectory so entry guards are stable across reboots
      # (recommended for anonymity). Remove for full amnesia.
      { directory = "/var/lib/tor"; user = "tor"; group = "tor"; mode = "0700"; }

      # /var/log is deliberately not persisted. Logs are volatile (RAM only,
      # journald Storage=volatile in hardening.nix) so nothing forensic
      # survives a reboot. Add "/var/log" here only if you need durable logs.
    ];

    # Long-lived secrets (the agenix identity, password file) live directly
    # at /persist/secrets. That path is on the persistent volume, so it needs
    # no bind-mount entry here.

    files = [
      # Stable machine-id. It never leaves the box (Tor scrubs it), but a
      # stable value avoids services regenerating identifiers each boot.
      # Remove this line for a fresh machine-id every boot.
      "/etc/machine-id"
    ];

    # Uncomment to keep specific home dirs across reboots (ephemeral by
    # default for maximum anonymity):
    # users.anon = {
    #   directories = [ ".ssh" "Downloads" { directory = ".gnupg"; mode = "0700"; } ];
    # };
  };

  systemd.tmpfiles.rules = [ "d /persist/secrets 0700 root root - -" ];
}
