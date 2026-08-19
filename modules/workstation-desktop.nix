##############################################################################
# KDE Plasma 6 desktop inside the workstation microVM (Whonix-Workstation).
#
# Runs in the isolated, fully-torified guest, never on the gateway. The guest
# stays a normal microVM systemd service; a virtio-GPU is added and the
# framebuffer is exported over a SPICE unix socket. A thin viewer on the host
# (modules/workstation-viewer.nix) shows it fullscreen. SDDM handles login.
#
# Toggle off for a headless/CLI-only workstation:
#   anon.workstation.desktop.enable = false;
#
# This is a large closure (Plasma) baked into the offline ISO. The display path
# (SPICE + GL + viewer) cannot be exercised without real hardware; expect to
# tune drivers/perms on first boot. See docs/workstation.md "KDE Plasma desktop".
##############################################################################
{ config, lib, pkgs, ... }:

let
  cfg = config.anon.workstation.desktop;
  # Host-side path where qemu exposes the guest's SPICE display. The host viewer
  # connects here. It lives in the VM's runtime state dir on the host.
  spiceSock = "/var/lib/microvms/workstation/spice.sock";
in {
  options.anon.workstation.desktop.enable =
    lib.mkEnableOption "the KDE Plasma 6 desktop in the workstation microVM" // {
      default = true;
    };

  config = lib.mkIf cfg.enable {
    ##########################################################################
    # GPU + SPICE display channel for the guest.
    #   graphics.enable: full-featured qemu + virtio-gpu-gl + egl-headless.
    #   extraArgs: export the GL framebuffer over a SPICE unix socket plus the
    #              spice-vdagent channel (clipboard/resize).
    ##########################################################################
    microvm.graphics.enable = true;
    microvm.graphics.backend = "headless";
    microvm.qemu.extraArgs = [
      "-spice" "unix=on,addr=${spiceSock},disable-ticketing=on,gl=on"
      "-device" "virtio-serial-pci"
      "-chardev" "spicevmc,id=vdagent,name=vdagent"
      "-device" "virtserialport,chardev=vdagent,name=com.redhat.spice.0"
    ];

    # A desktop needs more than the headless defaults. Tune to your host's RAM.
    microvm.mem = lib.mkForce 8192;
    microvm.vcpu = lib.mkForce 4;

    ##########################################################################
    # KDE Plasma 6 + SDDM. Log in as `user`; everything is torified.
    ##########################################################################
    services.xserver.enable = true;
    services.displayManager.sddm.enable = true;
    services.desktopManager.plasma6.enable = true;

    # spice-vdagent: clipboard sync + auto-resize to the viewer window.
    services.spice-vdagentd.enable = true;

    # Audio for the desktop (PipeWire, with PulseAudio emulation).
    security.rtkit.enable = true;
    services.pipewire = {
      enable = true;
      alsa.enable = true;
      pulse.enable = true;
    };

    # Minimal default app set (the recon/dev toolkit from workstation-tools.nix
    # is already present). Browser is Tor Browser, not vanilla Firefox: a
    # transparent Tor proxy does not anonymize browser fingerprint
    # (canvas/WebGL/fonts/screen); only Tor Browser's uniform fingerprint does.
    # TOR_TRANSPROXY=1 tells it to use the gateway's Tor (avoids Tor-over-Tor).
    environment.systemPackages = with pkgs; [
      kdePackages.konsole
      kdePackages.dolphin
      kdePackages.kate
      tor-browser
    ];
    environment.sessionVariables.TOR_TRANSPROXY = "1";
  };
}
