##############################################################################
# Host thin-client for the workstation's KDE desktop.
#
# The gateway stays headless; this is the only GUI: a minimal Wayland kiosk
# (cage) that launches a SPICE viewer fullscreen, showing the workstation
# microVM's SDDM/Plasma session (exported by modules/workstation-desktop.nix
# over a SPICE unix socket). Gateway services run independently.
#
# Toggle off for a headless gateway (drive the workstation via `microvm -c`):
#   anon.workstation.viewer.enable = false;
#
# The GL/SPICE/kiosk stack cannot be exercised without real hardware. Expect
# to tune it on first boot. See docs/workstation.md.
##############################################################################
{ config, lib, pkgs, ... }:

let
  cfg = config.anon.workstation.viewer;
  spiceSock = "/var/lib/microvms/workstation/spice.sock";
  viewerUser = "anon";

  # Only remote-viewer is used (plain SPICE over a unix socket), so build
  # virt-viewer without libvirt support. This drops libvirt -> xen ->
  # inetutils from the gateway closure; that inetutils ships telnetd with an
  # actively-exploited, unfixed auth bypass (CVE-2026-24061, CISA KEV). The
  # binary was dormant here, but not shipping it beats trusting that.
  virtViewer = pkgs.virt-viewer.overrideAttrs (old: {
    pname = old.pname + "-nolibvirt";
    buildInputs =
      builtins.filter (d: builtins.match "libvirt.*" (d.pname or "") == null)
        old.buildInputs;
    mesonFlags = old.mesonFlags ++ [ "-Dlibvirt=disabled" ];
  });

  # Wait for the VM's SPICE socket, then show it fullscreen; re-attach if the
  # VM (or the viewer) restarts.
  kiosk = pkgs.writeShellScript "ws-viewer" ''
    set -u
    while true; do
      until [ -S "${spiceSock}" ]; do sleep 1; done
      ${virtViewer}/bin/remote-viewer --full-screen \
        "spice+unix://${spiceSock}" || true
      sleep 2
    done
  '';
in {
  options.anon.workstation.viewer.enable =
    lib.mkEnableOption "the host thin-client that displays the workstation desktop" // {
      default = true;
    };

  config = lib.mkIf (cfg.enable && config.anon.workstation.enable) {
    # GPU stack for the kiosk compositor + GL-accelerated SPICE.
    hardware.graphics.enable = true;

    # The SPICE socket is created root-owned by qemu; hand it to the viewer user.
    # A .path unit re-runs this whenever the socket reappears (VM restarts).
    systemd.paths.spice-sock-perms = {
      wantedBy = [ "multi-user.target" ];
      pathConfig.PathExists = spiceSock;
    };
    systemd.services.spice-sock-perms = {
      description = "Grant ${viewerUser} access to the workstation SPICE socket";
      serviceConfig.Type = "oneshot";
      path = [ pkgs.coreutils ];
      script = ''chown ${viewerUser} "${spiceSock}" || true'';
    };

    # Interactive login into a single-app Wayland kiosk. tuigreet prompts for
    # gateway credentials (PAM) before launching cage+viewer. No auto-login:
    # an auto-logged-in kiosk would expose a passwordless shell if escaped.
    # Log in as `${viewerUser}`; the workstation's own SDDM is inside.
    services.greetd = {
      enable = true;
      settings.default_session = {
        command = "${pkgs.tuigreet}/bin/tuigreet --time --remember --cmd '${pkgs.cage}/bin/cage -s -- ${kiosk}'";
        user = "greeter";
      };
    };

    environment.systemPackages = [ virtViewer pkgs.cage pkgs.tuigreet ];
  };
}
