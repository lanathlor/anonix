##############################################################################
# QEMU VM test: the workstation microVM actually launches and boots.
#
# Everything up to this point was checked at eval time or by hand. Nothing
# proved that the VM the gateway is built around can start, and it could not:
# modules/microvm-host.nix created the volume directory 0700 root:root while
# microvm@.service runs as the unprivileged `microvm` user, so qemu could not
# create home.img. The unit failed, the SPICE socket never appeared, and the
# viewer's `until [ -S ... ]` loop showed a black screen forever with no error.
#
# Asserts, in order of how they failed in practice:
#   1. the service user can write the volume directory,
#   2. the unit comes up and stays up (not restart-looping),
#   3. qemu created the backing image,
#   4. the guest booted far enough to answer on the isolated bridge.
#
# Needs nested KVM: the gateway runs under KVM and the workstation runs inside
# it. Check with /sys/module/kvm_{intel,amd}/parameters/nested.
#
# TWO CHECKS COME OUT OF THIS FILE, because 4. needs a machine CI does not have:
#
#   workstation-starts       everything host-side, up to and including the
#                            viewer staying attached. Minutes. Runs in CI.
#   workstation-guest-boots  the same, plus `guestBoot` below: the guest
#                            finishes booting and reaches graphical.target.
#                            NOT run in CI -- see .github/workflows/ci.yml.
#
# The split is not squeamishness about a slow test. A GitHub-hosted runner is
# itself a VM, so the node here is L2 and the workstation microVM is L3, and an
# L3 guest traps its way through driver init: one CI run logged 622 s to reach
# "EDAC MC", 834 s to register PF_PACKET, and never got further, while burning
# a core -- with 6.8 GiB free and zero memory pressure, so this is virtualization
# depth, not resources. The same guest on a real host (L2) reaches
# graphical.target in 84 s. Run the guest check where the machine is real.
#
# Covered as far as it can be: the socket is created, accepts a connection, is
# handed to the viewer user, and remote-viewer attaches and stays attached.
#
# NOT covered, and not fixable here: whether the guest's desktop actually
# paints. That needs GL, which needs virtio-gpu-gl + egl-headless, which needs
# the full qemu (the framework ships a minimal one with neither GL nor SPICE)
# and a DRM render node -- and the nix build sandbox has no /dev/dri, so qemu
# exits at startup. The VM's GPU reports "-virgl" and the viewer shows a black
# display no matter how correct the configuration is. Verify that on hardware.
#
# Run: `nix build .#checks.x86_64-linux.workstation-starts -L`
#      `nix build .#checks.x86_64-linux.workstation-guest-boots -L`  (or
#      `just test-ws-guest`), on a host with nested KVM.
##############################################################################
{ system, nixpkgs, microvm, guestBoot ? false }:

let
  wsIp = "10.152.152.2";
  gwPassword = "anon-test-pw";

  # The guest inherits the node's pkgs, so it needs the same unfree allowance
  # hosts/anon carries (veracrypt is in the guest's base packages). It has to
  # come from the pkgs runNixOSTest is called on: per-node nixpkgs.config is
  # read-only, and node.pkgs is already set by the runner.
  pkgs = import nixpkgs {
    inherit system;
    config.allowUnfreePredicate = pkg:
      builtins.elem (nixpkgs.lib.getName pkg) [ "veracrypt" "wpscan" "waybackurls" ];
  };
in
pkgs.testers.runNixOSTest {
  name = if guestBoot then "workstation-guest-boots" else "workstation-starts";

  # Read the screen. A live SPICE socket proves qemu is listening, not that
  # anything is drawn -- the desktop can be dead behind a working socket.
  enableOCR = true;

  nodes.gateway = { lib, ... }: {
    imports = [
      microvm.nixosModules.host
      ../modules/microvm-host.nix
      ../modules/tor-gateway.nix
      ../modules/vpn.nix
      # Needed, not optional: workstation-viewer.nix is what sets
      # hardware.graphics.enable, and therefore what populates
      # /run/opengl-driver. Without it qemu's egl-headless cannot load the
      # Mesa GBM driver and the VM crash-loops. admin.nix supplies the `anon`
      # user that the SPICE socket is handed to.
      ../modules/workstation-viewer.nix
      ../modules/admin.nix
    ];

    networking.hostName = lib.mkForce "anon";
    users.users.anon.hashedPasswordFile = lib.mkForce null;
    users.users.anon.password = lib.mkForce gwPassword;

    anon.workstation.enable = true;
    # Desktop ON: it is what exports the SPICE socket, and a socket that exists
    # but refuses connections is the failure this test exists to catch. The
    # -device virtio-gpu below gives the VM a DRM render node so `gl=on` has
    # something to bind. Toolkit and wallets are orthogonal; leave them off.
    anon.workstation.desktop.enable = true;
    anon.workstation.toolkit.enable = false;
    anon.workstation.crypto.enable = false;

    environment.systemPackages = [ pkgs.socat ];

    # virtio-gpu exposes renderD128 as 0666, so an unprivileged qemu can open
    # it whether or not it has the render group -- which means this VM would
    # pass even with the GPU permissions broken. Real hardware ships
    # 0660 root:render. Match that, or the check is theatre.
    services.udev.extraRules = ''
      KERNEL=="renderD*", MODE="0660", GROUP="render"
      KERNEL=="card*", MODE="0660", GROUP="video"
    '';

    # Dummy VPN values to pass the placeholder assertions; the tunnel stays
    # down and is irrelevant to whether the microVM starts.
    anon.vpn.endpointIp = "192.0.2.1";
    anon.vpn.serverPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    anon.vpn.privateKeyFile = lib.mkForce "/etc/vpn-key-absent";

    # On the real host /persist is a LUKS-backed mount; here a plain directory
    # is enough. What matters is that the tmpfiles rules own it correctly.
    #
    # Sized to fit the smallest machine this runs on, which is a GitHub-hosted
    # runner: 4 vCPU / 16 GiB. The original 12 GiB here + 8 GiB inside asked
    # that runner for more than it has, once the nix builder is counted too:
    # the guest's RAM is host-anonymous memory two levels down (qemu backs it
    # with a memfd inside this VM, which qemu backs again on the runner), so
    # the runner has to hold it for real. 8 GiB here and 4 GiB inside leaves
    # headroom and still exceeds what Plasma needs to reach a greeter -- a
    # later run measured the guest touching 456 MiB of it, with 6.8 GiB free
    # and no memory pressure at all. Keep the sum well under 16 GiB.
    #
    # Note what this does NOT fix: the guest still crawls on a CI runner,
    # because it is an L3 guest there. That is why the guest-boot assertions
    # live in a separate check; see the header.
    virtualisation.memorySize = 8192;
    virtualisation.cores = 4;
    virtualisation.diskSize = 16384;

    # Guest-side overrides, merged as an extra module into the workstation
    # microVM's own NixOS evaluation (microvm.vms.<name>.config takes every
    # definition as a module, so this adds to -- does not replace -- the one
    # in modules/microvm-host.nix).
    microvm.vms.workstation.config = {
      # 4 GiB / 2 vCPU instead of the production 8 GiB / 4 vCPU that
      # workstation-desktop.nix mkForces: see the memory budget above, and
      # note this VM has 4 vCPUs total, so 4 for the guest oversubscribes
      # them. mkOverride 40 to outrank that mkForce (50). 4096 is the base
      # default from workstation.nix, and deliberately not 2048 -- qemu hangs
      # on exactly 2 GiB (microvm.nix#171). What is under test is that the VM
      # starts and boots, not the production RAM budget.
      microvm.mem = lib.mkOverride 40 4096;
      microvm.vcpu = lib.mkOverride 40 2;

      # Make the guest's serial console actually say what it is doing. The
      # production cmdline carries NixOS's default loglevel=4, so between the
      # early-printk lines and systemd's first status message the console is
      # SILENT -- and the boot check below judges the guest by whether its
      # console is still moving, which that silence makes meaningless (a
      # healthy guest looks identical to a wedged one, and CI read it as
      # wedged). At 7 the kernel narrates the whole boot down the same serial
      # port, so "silent" means stuck.
      boot.consoleLogLevel = 7;
    };
    # -cpu max: nested virtualisation for the guest inside this guest.
    # -device virtio-gpu: gives this VM a /dev/dri render node so the inner
    # qemu's virtio-gpu-gl/egl-headless has something to bind. 2D only, so
    # the guest's desktop cannot be made to paint in here; see the coverage
    # note at the top of this file.
    # -vga none: the framework leaves QEMU's default VGA in place, so adding
    # virtio-gpu without this gives the VM two displays -- cage composites on
    # one while the driver screenshots the other, and OCR sees a blank screen.
    virtualisation.qemu.options = [ "-cpu" "max" "-vga" "none" "-device" "virtio-gpu" ];

    # NOT disabled, deliberately. On the real gateway "Wait for Network to be
    # Online" fails (the killswitch means nothing is routable until the tunnel
    # is up, and it never comes up without VPN keys). wg-quick Requires= that
    # target, and microvm@ has Restart=always plus Requires= on its tap unit --
    # so network churn can bounce the VM, replace the SPICE socket, and drop
    # the viewer's connection. Masking wait-online here would hide that whole
    # class of failure, which is the state the gateway actually boots into.
  };

  testScript = ''
    gateway.wait_for_unit("multi-user.target")

    with subtest("nested KVM is available (else the rest is meaningless)"):
        gateway.succeed("test -e /dev/kvm")

    with subtest("the service user can write the volume directory"):
        # The original bug, stated directly: 0700 root:root vs User=microvm.
        owner = gateway.succeed(
            "stat -c %U /persist/microvms/workstation"
        ).strip()
        user = gateway.succeed(
            "systemctl show -p User --value microvm@workstation.service"
        ).strip()
        assert owner == user, (
            f"volume dir is owned by {owner!r} but the VM runs as {user!r}; "
            "qemu cannot create its disk image"
        )
        gateway.succeed(
            f"runuser -u {user} -- test -w /persist/microvms/workstation"
        )

    with subtest("the microVM unit comes up"):
        gateway.wait_for_unit("microvm@workstation.service")
        # A unit that starts, dies and restarts also 'comes up'. Require it to
        # still be the same invocation a few seconds later.
        inv = gateway.succeed(
            "systemctl show -p InvocationID --value microvm@workstation.service"
        ).strip()
        gateway.sleep(15)
        gateway.succeed("systemctl is-active microvm@workstation.service")
        assert inv == gateway.succeed(
            "systemctl show -p InvocationID --value microvm@workstation.service"
        ).strip(), "microvm@workstation restarted: it is crash-looping"

    with subtest("the inner qemu is actually accelerated by KVM"):
        # microvm.nix asks for `-M microvm,accel=kvm:tcg` AND `-enable-kvm`.
        # Today the latter wins, so a missing /dev/kvm is fatal (that is what
        # tests/workstation-no-kvm.nix pins). If it ever stops winning, the
        # fallback in that accel list means qemu boots the guest under TCG
        # instead -- orders of magnitude slower, and completely silent about
        # it. The guest would then "just be slow", which is exactly the
        # failure this file's later checks cannot tell from a hang. Ask the
        # kernel instead: an accelerated qemu holds /dev/kvm open.
        pid = gateway.succeed(
            "systemctl show -p MainPID --value microvm@workstation.service"
        ).strip()
        # No pipe into `grep -q` here: it exits on the first match, the writer
        # gets SIGPIPE, and the driver runs commands under `pipefail`, so the
        # check fails exactly when it succeeds. Ask find, and test its output.
        gateway.succeed(f'test -n "$(find /proc/{pid}/fd -lname /dev/kvm)"')

    with subtest("qemu created the backing image"):
        gateway.wait_for_file("/persist/microvms/workstation/home.img")
        gateway.succeed("test -s /persist/microvms/workstation/home.img")

    with subtest("no permission errors in the unit's journal"):
        # `log` is the driver's logger; do not shadow it.
        journal = gateway.succeed(
            "journalctl -u microvm@workstation -b --no-pager"
        )
        for bad in ["Permission denied", "could not access KVM"]:
            assert bad not in journal, f"{bad!r} in the microVM journal:\n{journal}"

    with subtest("the SPICE socket exists AND accepts a connection"):
        # The viewer only does `until [ -S ... ]`, so a stale socket left by a
        # qemu that created it and then died passes that check and then fails
        # with "unable to connect to the graphic server". Existence is not
        # enough: connect to it.
        sock = "/var/lib/microvms/workstation/spice.sock"
        gateway.wait_for_file(sock)
        gateway.succeed(f"test -S {sock}")
        gateway.succeed(f"timeout 5 socat -u OPEN:/dev/null UNIX-CONNECT:{sock}")

    with subtest("the viewer user owns the socket it must open"):
        # spice-sock-perms hands the qemu-created socket to the viewer user.
        gateway.wait_until_succeeds(
            f"test \"$(stat -c %U {sock})\" = anon", timeout=60
        )

    with subtest("the socket-perms unit fires once, not in a loop"):
        # A .path with PathExists= retriggers as soon as its unit finishes;
        # without RemainAfterExit it spins forever and floods the journal.
        # Checking the socket's owner does not catch it -- a spinning unit
        # sets it correctly every time -- so count the starts.
        starts = int(gateway.succeed(
            "journalctl -u spice-sock-perms -b --no-pager | grep -c Starting || true"
        ).strip())
        assert starts <= 5, (
            f"spice-sock-perms started {starts} times: the .path unit is "
            "retriggering in a loop"
        )

    with subtest("the greeter is actually drawn on screen"):
        # Proves cage is compositing and the kiosk session started, rather
        # than a black screen with a healthy-looking socket behind it.
        # tuigreet renders "Authenticate into <hostname>".
        gateway.wait_for_text("Authenticate into anon", timeout=180)
        gateway.screenshot("01-greeter")

    with subtest("logging in starts the viewer, and it STAYS connected"):
        gateway.send_chars("anon\n")
        gateway.sleep(4)
        gateway.send_chars("${gwPassword}\n")
        gateway.wait_until_succeeds("pgrep -f remote-viewer", timeout=120)

        # This is the user-visible failure, stated precisely. "unable to
        # connect to the graphic server" makes remote-viewer exit; the kiosk
        # loop then respawns it every 2s forever. A viewer that is merely
        # "running" proves nothing -- a respawning one is always running too.
        # Require the same process to survive.
        # Retries while the guest's SPICE server finishes coming up are normal;
        # a permanent respawn loop is not. Require the PID to hold still for
        # 20s at some point within ~5 minutes.
        def viewer_pid():
            return gateway.succeed("pgrep -f remote-viewer | head -1").strip()

        stable = False
        for _ in range(15):
            first = viewer_pid()
            gateway.sleep(20)
            if first == viewer_pid():
                stable = True
                break
        if not stable:
            print("=== ws-viewer log (the viewer's own stderr) ===")
            print(gateway.execute("journalctl -b -t ws-viewer --no-pager | tail -40")[1])
            print("=== greetd journal ===")
            print(gateway.execute("journalctl -u greetd -b --no-pager | tail -60")[1])
            print("=== anything mentioning viewer/spice ===")
            print(gateway.execute(
                "journalctl -b --no-pager | grep -iE 'viewer|spice|cage|gl' | tail -40")[1])
        assert stable, (
            "remote-viewer keeps being restarted: it exits and the kiosk loop "
            "respawns it, which is what 'unable to connect to the graphic "
            "server' looks like from outside"
        )
        gateway.screenshot("02-viewer-attached")

    with subtest("the microVM is not restarted underneath the viewer"):
        # microvm@ has Restart=always and Requires= its tap unit, so network
        # churn can bounce it. Each bounce replaces the SPICE socket and drops
        # the viewer, which then shows "unable to connect to the graphic
        # server" -- with the viewer still running, so no process-level check
        # sees it. Count actual starts.
        starts = int(gateway.succeed(
            "journalctl -u microvm@workstation -b --no-pager "
            "| grep -c 'Started.*microvm@workstation' || true"
        ).strip())
        assert starts <= 1, (
            f"microvm@workstation started {starts} times: the VM is being "
            "restarted, replacing the SPICE socket under the viewer"
        )
        # Same question asked of the socket itself.
        perms_starts = int(gateway.succeed(
            "journalctl -u spice-sock-perms -b --no-pager | grep -c Starting || true"
        ).strip())
        assert perms_starts <= 5, (
            f"spice-sock-perms fired {perms_starts} times: the socket keeps "
            "being recreated"
        )
  '' + nixpkgs.lib.optionalString guestBoot ''

    # ---- the guest itself ---------------------------------------------------
    # Only in the workstation-guest-boots check; see the header. Everything
    # above is the host's side of the microVM and runs everywhere. The guest is
    # reachable from here in exactly two ways: its serial console (qemu's
    # stdout, hence the unit's journal) and the isolated bridge. Both checks
    # below are judged by PROGRESS, not by a deadline: this guest is a VM
    # inside a VM booting Plasma off a 9p-mounted store, ~90s on an idle host
    # and several times that on a busy one (a flat timeout=300 failed on a
    # loaded machine and passed on the same derivation minutes later), so any
    # fixed deadline is either flaky or so long it hides a real hang. Keep
    # waiting while the console keeps moving; give up when it goes quiet,
    # which is a wedge rather than slowness. The caps are backstops.
    #
    # This only works because the guest's console is verbose: at the stock
    # loglevel=4 a healthy guest is silent for minutes at a time and the whole
    # heuristic is a coin flip. See boot.consoleLogLevel in the node above.
    # systemd colourises the unit description in its status lines, so the
    # guest's console carries "Reached target <ESC>[0;1;39mGraphical
    # Interface<ESC>[0m." -- a plain `"Reached target Graphical Interface" in
    # console` test does NOT match that, and only passes by way of the second,
    # uncoloured copy the guest's journald pushes through kmsg. Do not depend
    # on that copy: allow anything between the two halves.
    import re
    graphical = re.compile(r"Reached target[^\n]*Graphical Interface")

    def guest_console():
        return gateway.succeed(
            "journalctl -u microvm@workstation -b --no-pager"
        )

    def give_up(why, console):
        # Without this a failure here says only "timed out": the guest is
        # invisible from the host and nothing explains where it stopped.
        print(f"=== {why}; guest console, last 80 lines ===")
        print("\n".join(console.splitlines()[-80:]))
        print("=== microvm@workstation status ===")
        print(gateway.execute(
            "systemctl status --no-pager --full microvm@workstation"
        )[1])
        # Distinguishes the two ways a guest crawls rather than hangs. If the
        # box is out of memory -- the guest's RAM is host memory two levels
        # down, so once it swaps every first touch of a guest page is a
        # page-in from disk -- this shows it. If memory is plentiful and the
        # guest is still crawling, it is virtualization depth (an L3 guest
        # traps its way through driver init), which no budget here can fix.
        print("=== memory on the gateway ===")
        print(gateway.execute("free -m; cat /proc/pressure/memory 2>/dev/null")[1])
        raise AssertionError(why)

    def await_guest(done, why, cap=1800, quiet_budget=600):
        quiet, waited, console = 0, 0, guest_console()
        while not done():
            if quiet >= quiet_budget:
                give_up(
                    f"{why}: its console has been silent for "
                    f"{quiet_budget // 60} min, so it is wedged, not slow",
                    console,
                )
            if waited >= cap:
                give_up(
                    f"{why}: still not there after {cap // 60} min, though its "
                    "console is still moving",
                    console,
                )
            gateway.sleep(10)
            waited += 10
            previous, console = console, guest_console()
            quiet = 0 if console != previous else quiet + 10

    with subtest("the guest booted and claimed its address on the bridge"):
        # Checked before the desktop: it is the earliest guest-side milestone
        # and needs no console output at all, so a failure here says "the guest
        # never finished booting" while a failure below says "it booted but the
        # desktop did not come up".
        gateway.wait_for_unit("systemd-networkd.service")

        # Not a ping: the killswitch drops the gateway's own ICMP to the
        # workstation (KILLSWITCH-DROP-OUT on virbr-anon), by design. ARP sits
        # below that filter, so a resolved neighbour entry is the liveness
        # signal -- it means the guest booted and answered for ${wsIp}.
        def on_the_bridge():
            # `grep lladdr >/dev/null`, not `grep -q lladdr`: -q exits on the
            # first match and SIGPIPEs the writer, which under the driver's
            # `pipefail` shell turns a match into a failure.
            return gateway.execute(
                "ping -c1 -W1 ${wsIp} >/dev/null 2>&1 || true; "
                "ip neigh show ${wsIp} | grep lladdr >/dev/null"
            )[0] == 0

        await_guest(on_the_bridge, "the guest never answered on the bridge")

    with subtest("the guest's own display manager came up"):
        # As close to "the desktop works" as this can get. Whether SDDM's
        # pixels reach the viewer depends on GL, which needs a render node the
        # build sandbox does not have -- so assert the guest side started, and
        # leave the pixels to the hardware.
        await_guest(
            lambda: graphical.search(guest_console()) is not None,
            "the guest never reached graphical.target",
        )
        gateway.screenshot("03-viewer")
  '';
}
