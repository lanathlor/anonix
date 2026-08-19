##############################################################################
# Mandatory transparent Tor gateway + hard killswitch (Whonix-style).
#
# Traffic flow for every application on this machine (and, when
# `anon.torGateway.internal.enable`, for the isolated workstation microVM):
#
#   app TCP/DNS ──(nft nat redirect)──▶ Tor TransPort/DNSPort
#                                        │
#                                        ▼  Tor opens new conns as user `tor`
#                              default route = wg-tunnel (the VPN tunnel)
#                                        │
#                                        ▼  kernel WireGuard encapsulates
#                              UDP to the VPN endpoint on the physical NIC
#                                        ▼
#                              VPN ▶ Tor guard ▶ Tor network ▶ exit ▶ Internet
#
# Killswitch (nft output/forward, policy drop): only the Tor daemon's own
# sockets (which can only egress via the VPN tunnel) and encrypted WireGuard
# packets to the endpoint are allowed out. FORWARD is dropped, so
# internal-network traffic can never reach the physical NIC; it can only be
# REDIRECTed into Tor. If Tor is down it has nowhere to go; if the VPN is down
# Tor has no route. Either failure: zero packets leave.
##############################################################################
{ config, lib, pkgs, ... }:

let
  transPort = 9040; # Tor transparent proxy (redirect TCP here)
  dnsPort = 9053;   # Tor DNS resolver    (redirect :53 here)
  socksPort = 9050; # Tor SOCKS (nix-daemon fetches go here explicitly)

  ep = config.anon.vpn.endpointIp;
  epPort = toString config.anon.vpn.endpointPort;

  # Match Tor by its numeric UID. NixOS gives `tor` a static UID, and a number
  # resolves without /etc/passwd, so both the build-time `nft -c` check (which
  # runs in a sandbox without the tor user) and runtime work correctly.
  torUid = toString config.users.users.tor.uid;

  int = config.anon.torGateway.internal;

  # LAN-bypass (split-tunnel) is configured at runtime, not build time. The
  # baked ruleset carries an empty `lan_bypass` named set; lan-bypass.service
  # fills it from /persist/lan-bypass (written at install time or edited later).
  # An empty set means fully torified.
  bypassFile = "/persist/lan-bypass";
in {
  options.anon.torGateway.internal = {
    enable = lib.mkEnableOption ''
      transparently proxy an internal network (e.g. an isolated workstation
      microVM) through this gateway's Tor. Traffic arriving on the internal
      interface is REDIRECTed into Tor and never forwarded to the WAN'';

    interface = lib.mkOption {
      type = lib.types.str;
      default = "virbr-anon";
      description = "Host interface carrying the internal (workstation) network.";
    };

    address = lib.mkOption {
      type = lib.types.str;
      default = "10.152.152.1";
      description = "The gateway's address on the internal network.";
    };
  };

  config = {
    ##########################################################################
    # Tor daemon: client + transparent proxy + DNS resolver.
    ##########################################################################
    services.tor = {
      enable = true;
      client.enable = true;

      # Stream isolation on the SOCKS port: different destinations/ports get
      # separate circuits so activity is harder to correlate.
      client.socksListenAddress = {
        addr = "127.0.0.1";
        port = socksPort;
        IsolateDestAddr = true;
        IsolateDestPort = true;
      };

      settings = {
        # Transparent proxy: apps' TCP is NAT-redirected here. Per-destination
        # stream isolation gives different destinations separate circuits.
        # When serving the internal net, also bind on the internal address so
        # REDIRECTed workstation traffic lands on Tor.
        TransPort = [{
          addr = "127.0.0.1";
          port = transPort;
          IsolateDestAddr = true;
          IsolateDestPort = true;
        }] ++ lib.optional int.enable {
          addr = int.address;
          port = transPort;
          IsolateDestAddr = true;
          IsolateDestPort = true;
        };
        # DNS resolver: apps' UDP/TCP :53 is redirected here; also powers
        # AutomapHostsOnResolve so .onion addresses resolve transparently.
        DNSPort = [{
          addr = "127.0.0.1";
          port = dnsPort;
          IsolateDestAddr = true;
          IsolateDestPort = true;
        }] ++ lib.optional int.enable {
          addr = int.address;
          port = dnsPort;
          IsolateDestAddr = true;
          IsolateDestPort = true;
        };
        AutomapHostsOnResolve = true;
        VirtualAddrNetworkIPv4 = "10.192.0.0/10";

        # Side-channel/traffic-analysis hardening (Whonix parity).
        # Tor's seccomp sandbox is tuned for glibc's allocator. A system-wide
        # hardened allocator (environment.memoryAllocator.provider != "libc", e.g.
        # graphene-hardened on the gateway; see modules/side-channel.nix) uses
        # mprotect(PROT_NONE) + mremap patterns that Tor's filter can reject with
        # SIGSYS, crashing the daemon. Since the killswitch depends on Tor running,
        # we disable Tor's seccomp when such an allocator is active and rely on
        # hardened_malloc's heap hardening, AppArmor, the unprivileged `tor` user,
        # and the killswitch for containment. With the stock allocator (QEMU test
        # or hardenedMalloc off) Tor keeps its seccomp. To always keep Sandbox on,
        # set anon.sideChannel.hardenedMalloc = false on the gateway.
        Sandbox = config.environment.memoryAllocator.provider == "libc";
        ConnectionPadding = true;
        ReducedConnectionPadding = false;
        CircuitPadding = true;
        ReducedCircuitPadding = false;
        ClientUseIPv6 = false;
      };
    };

    # Start Tor only after the VPN tunnel is up, so it never attempts a
    # connection over the clearnet NIC. The oifname pin in the ruleset is the
    # hard guarantee; this closes the boot-time race.
    systemd.services.tor = {
      after = [ "wg-quick-wg-tunnel.service" ];
      wants = [ "wg-quick-wg-tunnel.service" ];
    };

    # Apply the runtime LAN-bypass list. Reads ${bypassFile} (one IPv4 per
    # line, # comments allowed), fills the nftables `lan_bypass` sets, and
    # enables ip_forward only if any hosts are listed. With no file the sets
    # stay empty and forwarding stays off (fully torified). Edit the file and
    # `systemctl restart lan-bypass` to update without a rebuild.
    systemd.services.lan-bypass = lib.mkIf int.enable {
      description = "Apply runtime LAN-bypass list from ${bypassFile}";
      after = [ "nftables.service" ];
      wants = [ "nftables.service" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.nftables pkgs.gawk pkgs.coreutils pkgs.procps ];
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
      script = ''
        set -u
        ips=$(awk '$1 !~ /^#/ && NF {print $1}' "${bypassFile}" 2>/dev/null | paste -sd, - || true)
        for t in "ip tor_nat" "inet tor_fw"; do
          nft flush set $t lan_bypass 2>/dev/null || true
          if [ -n "$ips" ]; then nft add element $t lan_bypass "{ $ips }" || true; fi
        done
        if [ -n "$ips" ]; then
          sysctl -w net.ipv4.ip_forward=1
          echo "[lan-bypass] enabled forwarding to: $ips"
        else
          sysctl -w net.ipv4.ip_forward=0
          echo "[lan-bypass] no hosts configured; fully torified"
        fi
      '';
    };

    ##########################################################################
    # No IPv6. Tor's transparent proxy is v4-only; an unproxied v6 route is a
    # classic deanonymization leak.
    ##########################################################################
    boot.kernel.sysctl = {
      "net.ipv6.conf.all.disable_ipv6" = 1;
      "net.ipv6.conf.default.disable_ipv6" = 1;
      "net.ipv6.conf.lo.disable_ipv6" = 0;
      # Off by default (fully torified). lan-bypass.service raises this to 1
      # only if /persist/lan-bypass lists hosts; the forward chain permits only
      # those exact @lan_bypass destinations.
      "net.ipv4.ip_forward" = 0;
    };

    ##########################################################################
    # The firewall IS the killswitch.
    ##########################################################################
    networking.firewall.enable = false;
    networking.nftables.enable = true;
    networking.nftables.ruleset = ''
      ######################################################################
      # NAT: transparently redirect application traffic into Tor.
      ######################################################################
      table ip tor_nat {
        ${lib.optionalString int.enable ''
        # Runtime-populated LAN-bypass set (empty here = fully torified).
        # lan-bypass.service fills it from ${bypassFile}.
        set lan_bypass { type ipv4_addr; }

        chain prerouting {
          type nat hook prerouting priority -100; policy accept;
          # LAN bypass: traffic to these IPs is forwarded + masqueraded out the
          # physical NIC instead of being redirected into Tor. Empty set: inert.
          iifname "${int.interface}" ip daddr @lan_bypass return
          # Traffic from the internal (workstation) network -> Tor.
          iifname "${int.interface}" meta l4proto { tcp, udp } th dport 53 redirect to :${toString dnsPort}
          iifname "${int.interface}" meta l4proto tcp redirect to :${toString transPort}
          # Any other L4 from the internal net is left un-redirected and dropped
          # by the filter INPUT chain. This deliberately includes QUIC/HTTP-3
          # (UDP 443): UDP cannot traverse Tor, so allowing it would be a
          # clearnet leak. Dropping it makes browsers fall back to TCP HTTP/2,
          # which is torified. To reduce stalls, disable QUIC in the browser.
        }

        chain postrouting {
          type nat hook postrouting priority 100; policy accept;
          # Masquerade bypass traffic behind the gateway's NIC so the LAN host
          # can route replies back.
          oifname != "${int.interface}" ip daddr @lan_bypass masquerade
        }
        ''}

        chain output {
          type nat hook output priority -100; policy accept;

          # Tor's own traffic must never be redirected (would loop forever).
          meta skuid ${torUid} return

          # DNS -> Tor's DNSPort. Must precede the loopback returns below: the
          # host resolver is 127.0.0.1, so gateway DNS is destined for loopback,
          # and nothing listens on 127.0.0.1:53 (only Tor's DNSPort answers).
          # Tor is already skuid-returned above so this cannot loop. Workstation
          # DNS is handled in prerouting; this covers on-gateway name resolution.
          meta l4proto { tcp, udp } th dport 53 redirect to :${toString dnsPort}

          # Never touch other loopback traffic (e.g. Tor's SOCKS on 9050).
          oifname "lo" return
          ip daddr 127.0.0.0/8 return

          # All remaining TCP -> Tor's TransPort.
          meta l4proto tcp redirect to :${toString transPort}
        }
      }

      ######################################################################
      # FILTER: default-drop killswitch. `inet` so it covers IPv4 and IPv6.
      ######################################################################
      table inet tor_fw {
        ${lib.optionalString int.enable ''
        # Runtime-populated LAN-bypass set (mirrors the one in tor_nat).
        set lan_bypass { type ipv4_addr; }
        ''}
        chain input {
          type filter hook input priority 0; policy drop;

          iifname "lo" accept
          ct state established,related accept
          ct state invalid drop

          # Encrypted WireGuard packets coming back from the VPN server.
          ip saddr ${ep} udp sport ${epPort} accept

          # DHCP replies (obtain a LAN address on the physical NIC).
          udp sport 67 udp dport 68 accept
          ${lib.optionalString int.enable ''
          # Internal network may reach ONLY Tor's transparent + DNS ports
          # (the packets have already been REDIRECTed to these ports).
          iifname "${int.interface}" tcp dport ${toString transPort} accept
          iifname "${int.interface}" tcp dport ${toString dnsPort} accept
          iifname "${int.interface}" udp dport ${toString dnsPort} accept
          ''}
        }

        chain forward {
          # Drop by default. Workstation packets can never be forwarded to the
          # WAN except to the explicit LAN-bypass destinations below, if any.
          type filter hook forward priority 0; policy drop;
          ${lib.optionalString int.enable ''
          # Established/return traffic for allowed bypass flows.
          ct state established,related accept
          # New flows to @lan_bypass hosts only (empty set: nothing forwarded;
          # ip_forward stays 0 unless lan-bypass.service turns it on).
          iifname "${int.interface}" ip daddr @lan_bypass accept
          ''}
        }

        chain output {
          type filter hook output priority 0; policy drop;

          # Loopback, incl. the app->Tor redirected packets (their oif is lo).
          oifname "lo" accept
          ${lib.optionalString int.enable ''
          # Return traffic to the workstation for connections it opened to our
          # Tor TransPort/DNSPort. The workstation's TCP/DNS is REDIRECTed to Tor
          # on ${int.address}; Tor's replies egress oifname "${int.interface}" and
          # without this rule hit the default-drop policy (handshakes never
          # complete). Scoped to established,related only: opens no new egress.
          # The internal interface has no WAN route, so the killswitch stays
          # fail-closed even with this rule.
          oifname "${int.interface}" ct state established,related accept
          ''}

          # Return traffic only on the VPN tunnel. A blanket "ct state
          # established accept" on every interface would let in-flight Tor streams
          # spill onto the clearnet NIC if the tunnel drops. The WireGuard packets
          # to the endpoint are matched by their own daddr rule below, so this
          # pin does not break the tunnel.
          oifname "wg-tunnel" ct state established,related accept

          # Tor may only egress via the VPN tunnel. If the tunnel is down,
          # Tor's packets have oif=<physical NIC>, do not match, and are dropped.
          # Without this pin, a dropped tunnel leaves the DHCP default route in
          # place and Tor would egress over clearnet, leaking the real IP to the
          # guard and "this subscriber uses Tor" to the ISP.
          oifname "wg-tunnel" meta skuid ${torUid} accept

          # Encrypted WireGuard packets to the VPN endpoint (kernel-generated,
          # no socket uid; must be allowed by destination address).
          ip daddr ${ep} udp dport ${epPort} accept

          # DHCP requests to get on the LAN.
          udp sport 68 udp dport 67 accept

          # Log (rate-limited) anything about to be dropped: a canary for any
          # process attempting egress outside the Tor/VPN path. The packet
          # is still dropped; this only makes leaks visible.
          #   journalctl -k -g 'KILLSWITCH-DROP'
          # Logs are volatile/RAM-only. Forward-chain drops are not logged;
          # workstation clearnet attempts are expected and would be noise.
          limit rate 10/minute burst 5 packets log prefix "KILLSWITCH-DROP-OUT: " level warn

          # Everything else (clearnet, IPv6, stray UDP including QUIC/HTTP-3 on
          # UDP 443) is dropped. Apps fall back to TCP, which is torified.
        }
      }
    '';

    assertions = [{
      assertion = config.anon.vpn.endpointIp != "PLACEHOLDER_ENDPOINT_IP";
      message = ''
        anon.vpn.endpointIp is still the placeholder. Fill in
        modules/vpn.nix before deploying; the killswitch needs the real
        endpoint IP to allow WireGuard packets out. (Bypassed in the QEMU test.)
      '';
    }];
  };
}
