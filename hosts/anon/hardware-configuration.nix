##############################################################################
# Generic hardware configuration, not machine-specific (do not run
# nixos-generate-config). The disk layout lives in modules/disk.nix. This file
# carries initrd storage drivers for all common x86_64 boot paths plus CPU
# microcode. For unusual controllers, add their module to
# boot.initrd.availableKernelModules.
##############################################################################
{ config, lib, pkgs, modulesPath, ... }:

{
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];

  # Broad, generic storage/boot driver set; no per-machine generation needed.
  boot.initrd.availableKernelModules = [
    # SATA / IDE
    "ahci" "ata_piix" "sata_nv" "sd_mod" "sr_mod"
    # NVMe
    "nvme"
    # USB (boot from USB, USB keyboards for the LUKS passphrase)
    "xhci_pci" "ehci_pci" "ohci_pci" "uhci_hcd" "usbhid" "usb_storage" "uas"
    # virtio (VMs / cloud)
    "virtio_pci" "virtio_blk" "virtio_scsi" "virtio_net"
  ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ ];
  boot.extraModulePackages = [ ];

  # CPU microcode: enable both vendors so the generic image works on Intel and AMD.
  hardware.cpu.intel.updateMicrocode = lib.mkDefault true;
  hardware.cpu.amd.updateMicrocode = lib.mkDefault true;

  # No swap: swap can persist secrets to disk. Add an encrypted swap partition
  # to modules/disk.nix if needed.
  swapDevices = [ ];

  nixpkgs.hostPlatform = lib.mkDefault "x86_64-linux";
}
