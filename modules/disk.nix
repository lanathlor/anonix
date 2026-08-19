##############################################################################
# Declarative disk layout (disko). Single source of truth for both
# partitioning and the runtime fileSystems/LUKS. No hand-written filesystem
# block and no `nixos-generate-config` step needed. The offline installer
# wipes and formats a disk to exactly this.
#
# Layout (GPT):
#   ESP  (vfat, label BOOT)                 -> /boot     (Secure Boot protects it)
#   LUKS "nixcrypt"    -> ext4 "nix"        -> /nix      (persistent, encrypted)
#   LUKS "persistcrypt"-> ext4 "persist"    -> /persist  (secrets, encrypted)
#   tmpfs                                   -> /         (wiped every boot)
#
# LUKS is unlocked in the initrd by passphrase. The LUKS labels nixcrypt and
# persistcrypt make the containers resolve via /dev/disk/by-label, independent
# of the disk device name.
##############################################################################
{ lib, ... }:

{
  disko.devices = {
    disk.main = {
      type = "disk";
      # Target disk. Set to the host's disk before building the ISO (`lsblk`);
      # the offline installer wipes exactly this device.
      device = lib.mkDefault "/dev/nvme0n1";
      content = {
        type = "gpt";
        partitions = {
          ESP = {
            priority = 1;
            size = "1G";
            type = "EF00";
            content = {
              type = "filesystem";
              format = "vfat";
              mountpoint = "/boot";
              mountOptions = [ "fmask=0077" "dmask=0077" ];
              extraArgs = [ "-n" "BOOT" ];
            };
          };

          nix = {
            size = "64G"; # the Nix store; grow if you install a lot
            content = {
              type = "luks";
              name = "nix";
              # LUKS2 header label -> /dev/disk/by-label/nixcrypt.
              extraFormatArgs = [ "--label" "nixcrypt" ];
              # TRIM inside LUKS is disabled: it leaks the used/free block map.
              settings.allowDiscards = false;
              content = {
                type = "filesystem";
                format = "ext4";
                mountpoint = "/nix";
                extraArgs = [ "-L" "nix" ];
              };
            };
          };

          persist = {
            size = "100%"; # remainder: holds age identity and Secure Boot keys
            content = {
              type = "luks";
              name = "persist";
              extraFormatArgs = [ "--label" "persistcrypt" ];
              settings.allowDiscards = false;
              content = {
                type = "filesystem";
                format = "ext4";
                mountpoint = "/persist";
                extraArgs = [ "-L" "persist" ];
              };
            };
          };
        };
      };
    };

    # Root is RAM only, wiped on every boot (impermanence).
    nodev."/" = {
      fsType = "tmpfs";
      mountOptions = [ "defaults" "size=4G" "mode=0755" ];
    };
  };

  # Both must be mounted before stage-2 / activation: /nix holds the store and
  # /persist holds the agenix identity that decrypts the VPN key at boot.
  fileSystems."/nix".neededForBoot = true;
  fileSystems."/persist".neededForBoot = true;
}
