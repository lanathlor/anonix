##############################################################################
# QEMU VM repro: what the gateway does on a machine WITHOUT /dev/kvm.
#
# Field report (HP laptop, 2026-09-14): boot looks normal, tuigreet comes up,
# but logging in yields a remote-viewer dialog "Unable to connect to the
# graphic server spice+unix:///var/lib/microvms/workstation/spice.sock".
# The journal shows microvm@workstation crash-looping:
#   qemu: Could not access KVM kernel module: No such file or directory
#   qemu: failed to initialize kvm: No such file or directory
# i.e. /dev/kvm is missing (kvm-intel cannot load: VT-x off in firmware or
# unsupported CPU). microvm.nix runs qemu with KVM required, the unit has
# Restart=always, so it loops forever and the user only ever sees the socket
# error, with no hint that virtualization is the problem.
#
# This test is that laptop: same node as tests/workstation-starts.nix, but
# `-cpu qemu64` (no VMX flag) instead of `-cpu max`, so the gateway VM has no
# nested virtualization and /dev/kvm never appears -- regardless of whether
# the build host itself has KVM. It asserts the failure signature, proving
# the repro; it is NOT an assertion of desired behaviour. Once the gateway
# handles missing KVM properly (fail loudly / TCG fallback), rewrite the
# expectations here to pin the fix.
#
# Run: `nix build .#checks.x86_64-linux.workstation-no-kvm-repro.driver` and
# execute the driver (works under TCG; no KVM needed, that being the point).
##############################################################################
{ system, nixpkgs, microvm }:

let
  gwPassword = "anon-test-pw";

  pkgs = import nixpkgs {
    inherit system;
    config.allowUnfreePredicate = pkg:
      builtins.elem (nixpkgs.lib.getName pkg) [ "veracrypt" "wpscan" "waybackurls" ];
  };
in
pkgs.testers.runNixOSTest {
  name = "workstation-no-kvm-repro";

  enableOCR = true;

  nodes.gateway = { lib, ... }: {
    imports = [
      microvm.nixosModules.host
      ../modules/microvm-host.nix
      ../modules/tor-gateway.nix
      ../modules/vpn.nix
      ../modules/workstation-viewer.nix
      ../modules/admin.nix
    ];

    networking.hostName = lib.mkForce "anon";
    users.users.anon.hashedPasswordFile = lib.mkForce null;
    users.users.anon.password = lib.mkForce gwPassword;

    anon.workstation.enable = true;
    anon.workstation.desktop.enable = true;
    anon.workstation.toolkit.enable = false;
    anon.workstation.crypto.enable = false;

    # Dummy VPN values to pass the placeholder assertions, as everywhere else.
    anon.vpn.endpointIp = "192.0.2.1";
    anon.vpn.serverPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    anon.vpn.privateKeyFile = lib.mkForce "/etc/vpn-key-absent";

    environment.systemPackages = [ pkgs.socat ];

    # The inner qemu never boots its guest, so no room for the guest's 8 GiB
    # is needed; enough for the gateway itself plus qemu's startup attempts.
    virtualisation.memorySize = 4096;
    virtualisation.cores = 2;
    virtualisation.diskSize = 16384;
    # THE POINT OF THIS TEST: qemu64 has no vmx/svm flag, so kvm-intel/kvm-amd
    # cannot load and /dev/kvm never exists inside this VM -- the laptop with
    # virtualization disabled in firmware, faithfully. (Last -cpu wins, so
    # this overrides whatever the test framework passes.) virtio-gpu still
    # provides a render node like real hardware; -vga none as in
    # workstation-starts so OCR reads the display cage composites on.
    virtualisation.qemu.options = [ "-cpu" "qemu64" "-vga" "none" "-device" "virtio-gpu" ];
  };

  testScript = ''
    gateway.wait_for_unit("multi-user.target")

    with subtest("repro precondition: no /dev/kvm on the gateway"):
        gateway.fail("test -e /dev/kvm")

    with subtest("microvm@workstation dies with the KVM error from the field"):
        gateway.wait_until_succeeds(
            "journalctl -u microvm@workstation -b --no-pager "
            "| grep -q 'Could not access KVM kernel module'",
            timeout=300,
        )

    with subtest("...and crash-loops instead of failing once, loudly"):
        # Restart=always + a qemu that exits within a second: the restart
        # counter climbs forever. Three scheduled restarts is a loop.
        gateway.wait_until_succeeds(
            "test \"$(journalctl -u microvm@workstation -b --no-pager "
            "| grep -c 'Scheduled restart job')\" -ge 3",
            timeout=180,
        )
        print(gateway.execute(
            "journalctl -u microvm@workstation -b --no-pager | tail -25")[1])

    with subtest("qemu leaves a STALE SPICE socket: file exists, nobody listens"):
        # qemu binds the SPICE unix socket during startup, then dies at accel
        # init on the missing /dev/kvm without unlinking it. The viewer's
        # `[ -S ... ]` check therefore passes against a dead socket. Verified
        # here: the file is a socket, and connecting to it fails. (Retried,
        # not a one-shot fail(): each ~5s restart gives qemu a sub-second
        # window where the socket briefly has a listener again.)
        sock = "/var/lib/microvms/workstation/spice.sock"
        gateway.wait_for_file(sock)
        gateway.succeed(f"test -S {sock}")
        gateway.wait_until_succeeds(
            f"! timeout 5 socat -u OPEN:/dev/null UNIX-CONNECT:{sock}",
            timeout=60,
        )

    with subtest("the greeter still comes up as if nothing were wrong"):
        gateway.wait_for_text("Authenticate into anon", timeout=600)
        gateway.screenshot("01-greeter")

    with subtest("logging in shows the exact dialog from the field"):
        gateway.send_chars("anon\n")
        gateway.sleep(4)
        gateway.send_chars("${gwPassword}\n")
        # The kiosk sees the stale socket and hands it to remote-viewer...
        gateway.wait_until_succeeds(
            "journalctl -b -t ws-viewer --no-pager "
            "| grep -Eq 'attaching to|waiting for the workstation SPICE socket'",
            timeout=300,
        )
        # ...which fails to connect and parks a modal GTK dialog on screen:
        # 'Unable to connect to the graphic server
        #  spice+unix:///var/lib/microvms/workstation/spice.sock'
        # -- the photographed failure, verbatim. It never reaches the journal
        # (it is a dialog, not stderr), and the process stays alive waiting
        # for OK, so no journal- or process-level check sees anything wrong.
        # Read the screen -- but NOT with wait_for_text: the frame is almost
        # entirely black with one small dialog, and the driver's OCR pipeline
        # finds no text in it at any page-segmentation mode (verified by
        # hand). Trim the black border and scale up first; then tesseract
        # reads the dialog verbatim.
        import shutil
        import subprocess
        import tempfile

        magick = shutil.which("magick") or "convert"

        def dialog_text() -> str:
            # PPM/PGM end to end: the driver bundles a delegate-less
            # imagemagick that cannot read PNG at all, so take qemu's native
            # screendump (PPM) instead of machine.screenshot(). magick also
            # exits 1 on a fully uniform (still all-black) frame (-trim has
            # nothing to keep): not an error, return "" and let the retry
            # loop come back.
            d = tempfile.mkdtemp()
            gateway.send_monitor_command(f"screendump {d}/shot.ppm")
            crop = subprocess.run(
                [magick, f"{d}/shot.ppm", "-trim", "+repage", "-resize",
                 "300%", "-colorspace", "Gray", "-normalize", f"{d}/ocr.pgm"],
                capture_output=True,
            )
            if crop.returncode != 0:
                return ""
            ocr = subprocess.run(
                ["tesseract", f"{d}/ocr.pgm", "-", "--psm", "6"],
                capture_output=True, text=True,
            )
            return ocr.stdout if ocr.returncode == 0 else ""

        text = ""
        for _ in range(30):
            text = dialog_text()
            if "Unable to connect" in text:
                break
            gateway.sleep(10)
        print(f"=== screen text ===\n{text}")
        assert "Unable to connect to the graphic server" in text, (
            "the socket-error dialog is not on screen; the field failure "
            f"did not reproduce. OCR saw:\n{text}"
        )
        assert "spice.sock" in text.replace("\n", ""), (
            f"dialog does not name the SPICE socket. OCR saw:\n{text}"
        )
        gateway.screenshot("02-socket-error-dialog")
  '';
}
