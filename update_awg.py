#!/usr/bin/env python3
"""
Generate and remotely apply an AmneziaWG RouterOS install script from a .conf file.

Produces scripts matching the custom template (awg-de-04.06.rsc style).
Workflow: generate .rsc → SSH uninstall old → SFTP upload → /import

Requires:
    pip install paramiko python-dotenv

Usage:
    python3 update_awg.py <config.conf> <tag> [options]

    --env PATH         .env file path (default: .env)
    --output PATH      also write generated .rsc to this file
    --dry-run          print generated script only, no SSH
    --generate-only    write .rsc file, skip SSH

Required RouterOS SSH permissions for the connecting user:
    /user/group/set <group> policy=ssh,read,write,policy,ftp

Examples:
    python3 update_awg.py de-0406.conf awg-de --dry-run
    python3 update_awg.py de-0406.conf awg-de --output de-new.rsc
    python3 update_awg.py de-0406.conf awg-de
"""

import argparse
import ipaddress
import random
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import paramiko
except ImportError:
    sys.exit("Missing dependency: pip install paramiko")

try:
    from dotenv import dotenv_values
except ImportError:
    sys.exit("Missing dependency: pip install python-dotenv")


# ── RSC template ───────────────────────────────────────────────────────────────
# Based on awg-de-04.06.rsc (custom style, no DNS section, custom routes).
# Placeholders use %%NAME%% to avoid conflicts with RouterOS { } syntax.

RSC_TEMPLATE = """\
# 0. Check prerequisites
:if ([:len [/system/package/find where name="container" disabled=no]] = 0) do={
  :put "Container package is not installed or disabled. Install it and reboot."
  :error "Usage: /system/device-mode/update container=yes"
}

# 1. Uninstall script
/system/script/add name=%%TAG%%-uninstall comment=%%TAG%% source={
  :put "Uninstalling AmneziaWG..."
  :log info "Uninstalling AmneziaWG..."
  /ip/route/remove [find where comment=%%TAG%%-tunnel]
  :do { /tool/netwatch/remove [find where comment=Monitor-%%TAG_UPPER%%] } on-error={}
  :do { /ip/route/remove [find where comment=Monitor-%%TAG_UPPER%%] } on-error={}
  /container/stop [find where interface=veth-%%TAG%%]
  :delay 7s
  /interface/list/member/remove [find where interface=wg-%%TAG%%]
  /container/remove [find where interface=veth-%%TAG%%]
  /container/envs/remove [find where list="%%TAG%%-env"]
  /ip/firewall/nat/remove [find where out-interface="wg-%%TAG%%"]
  /ip/address/remove [find where address="%%VETH_GATEWAY%%/30"]
  /interface/veth/remove [find where name="veth-%%TAG%%"]
  /interface/wireguard/peers/remove [find where interface="wg-%%TAG%%"]
  /ip/address/remove [find where interface="wg-%%TAG%%"]
  /interface/wireguard/remove [find where name="wg-%%TAG%%"]
  :do { /file/remove [find where name~"%%TAG%%.+tar"] } on-error={}
  :do { /file/remove [find where name="disk1/%%TAG%%"] } on-error={}
  :put "Uninstall AmneziaWG Proxy complete!"
  :log info "Uninstall AmneziaWG Proxy complete!"
  /system/script/remove [find where name=%%TAG%%-uninstall]
}

# 2. Network infrastructure
/interface/veth/add name=veth-%%TAG%% address=%%VETH_CONTAINER%% gateway=%%VETH_GATEWAY%%
/ip/address/add address=%%VETH_GATEWAY%%/30 interface=veth-%%TAG%%

# 3. WireGuard interface (MikroTik derives the public key automatically)
/interface/wireguard/add name=wg-%%TAG%% private-key="%%PRIVATE_KEY%%" listen-port=%%WG_LISTEN_PORT%% disabled=yes mtu=%%WG_MTU%%
/interface/wireguard/peers/add interface=wg-%%TAG%% name=%%TAG%% public-key="%%SERVER_PUB%%" preshared-key="%%PRESHARED_KEY%%" endpoint-address=%%VETH_CONTAINER_IP%% endpoint-port=%%AWG_LISTEN_PORT%% allowed-address=0.0.0.0/0,::/0 persistent-keepalive=%%WG_KEEPALIVE%%
/ip/address/add address=%%CLIENT_ADDRESS%% interface=wg-%%TAG%%
/interface/list/member/add interface=wg-%%TAG%% list=%%WG_LIST%%
/ip/route/set [find where comment=Monitor-%%TAG_UPPER%%] gateway=wg-%%TAG%%
/ip/route/set [find where comment=Route-%%TAG_UPPER%%] gateway=wg-%%TAG%%

# 4. Container environment variables
/container/envs/add list=%%TAG%%-env key=AWG_LISTEN value=":%%AWG_LISTEN_PORT%%"
/container/envs/add list=%%TAG%%-env key=AWG_REMOTE value="%%ENDPOINT%%"
/container/envs/add list=%%TAG%%-env key=AWG_JC value="%%JC%%"
/container/envs/add list=%%TAG%%-env key=AWG_JMIN value="%%JMIN%%"
/container/envs/add list=%%TAG%%-env key=AWG_JMAX value="%%JMAX%%"
/container/envs/add list=%%TAG%%-env key=AWG_S1 value="%%S1%%"
/container/envs/add list=%%TAG%%-env key=AWG_S2 value="%%S2%%"
/container/envs/add list=%%TAG%%-env key=AWG_H1 value="%%H1%%"
/container/envs/add list=%%TAG%%-env key=AWG_H2 value="%%H2%%"
/container/envs/add list=%%TAG%%-env key=AWG_H3 value="%%H3%%"
/container/envs/add list=%%TAG%%-env key=AWG_H4 value="%%H4%%"
/container/envs/add list=%%TAG%%-env key=AWG_SERVER_PUB value="%%SERVER_PUB%%"
/container/envs/add list=%%TAG%%-env key=AWG_CLIENT_PUB value=[/interface/wireguard/get [find name=wg-%%TAG%%] public-key]
/container/envs/add list=%%TAG%%-env key=AWG_I1 value="%%AWG_I1%%"
%%OPTIONAL_ENV%%

# 6. Download, create and start container
{
  :local arch [/system/resource/get architecture-name]
  :local ver [/system/resource/get version]
  :local dotPos [:find $ver "."]
  :local rest [:pick $ver ($dotPos + 1) [:len $ver]]
  :local endPos [:find $rest "."]
  :if ([:typeof $endPos] = "nil") do={ :set endPos [:find $rest " "] }
  :local minor [:tonum [:pick $rest 0 $endPos]]
  :local suffix ""
  :if ($minor <= 20) do={ :set suffix "-7.20-Docker" }
  :local file ""
  :if ($arch = "arm64") do={ :set file ("awg-proxy-arm64" . $suffix . ".tar.gz") }
  :if ($arch = "arm") do={ :set file ("awg-proxy-arm" . $suffix . ".tar.gz") }
  :if ($arch ~ "x86") do={ :set file ("awg-proxy-amd64" . $suffix . ".tar.gz") }
  :if ($file = "") do={ :error "Unsupported architecture: $arch" }
  :local url "https://github.com/timbrs/amneziawg-mikrotik/releases/latest/download/$file"
  :local filePath $file
  :if ([:len [/file/find where name=$filePath]] = 0) do={
    :local freeStorage 0
    :set freeStorage [/system/resource/get free-hdd-space]
    :if ($freeStorage < 5242880) do={
      :put ("WARNING: Low disk space (" . ($freeStorage / 1048576) . "MB free). Need at least 5MB.")
      :put "See: https://github.com/timbrs/amneziawg-mikrotik"
      :error "Insufficient disk space"
    }
    :put ("Fetching: $url -> " . $filePath)
    /tool/fetch url=$url dst-path=$filePath http-max-redirect-count=10
  } else={
    :put ("File already exists: " . $filePath)
  }
  /container/add file=$filePath interface=veth-%%TAG%% envlist=%%TAG%%-env hostname=%%TAG%% name=%%TAG%% root-dir=disk1/%%TAG%% logging=no start-on-boot=yes comment=%%TAG%%
  :if ($minor > 20) do={ [:parse "/container/set [find where interface=veth-%%TAG%%] shm-size=4M"] }
  /file/remove $filePath
  :local freeMem [/system/resource/get free-memory]
  :if ($freeMem < 16777216) do={
    :put ("WARNING: Low memory (" . ($freeMem / 1048576) . "MB free). 16MB+ recommended.")
  }
  /container/start [find where interface=veth-%%TAG%%]
  :do { /file/remove [find where name="console-dump.txt"] } on-error={}
  :put "Waiting for container to start..."
  :delay 5s
  /interface/wireguard/enable wg-%%TAG%%
  :put "WireGuard interface enabled"
  :put "Installation complete!"
}
"""


# ── Conf parsing ───────────────────────────────────────────────────────────────

def parse_conf(conf_path: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current: Optional[str] = None
    with open(conf_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1]
                sections[current] = {}
            elif "=" in line and current is not None:
                key, _, value = line.partition("=")
                sections[current][key.strip()] = value.strip()
    return sections


def compute_veth(gateway: str) -> tuple[str, str, str]:
    """From gateway IP (e.g. 172.16.0.1) derive (container_ip, container_cidr, subnet)."""
    gw = ipaddress.IPv4Address(gateway)
    container = ipaddress.IPv4Address(int(gw) + 1)
    network = ipaddress.IPv4Network(f"{gw}/30", strict=False)
    return str(container), f"{container}/30", str(network)


# ── DNS candidates for monitor routes (non-RU, non-default) ───────────────────
# Excluded by default: 1.1.1.1, 1.0.0.1 (Cloudflare), 8.8.8.8, 8.8.4.4 (Google)
# Excluded: any RU providers (Yandex 77.88.x.x, MSK-IX 62.76.x.x, НСДИ 195.208.x.x)
DNS_CANDIDATES = [
    # Quad9 (EU/Swiss)
    "9.9.9.9", "9.9.9.10", "149.112.112.112", "149.112.112.10",
    # Level3 / Lumen (US)
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
    # OpenDNS / Cisco (US)
    "208.67.222.222", "208.67.220.220", "208.67.222.220", "208.67.220.222",
    # Verisign (US)
    "64.6.64.6", "64.6.65.6",
    # G-Core (EU)
    "95.85.95.85", "2.56.220.2",
    # DNS.SB (EU)
    "185.222.222.222", "45.11.45.11",
    # TREX (EU/FI)
    "195.140.195.21", "195.140.195.22",
]


# ── Router resource queries ────────────────────────────────────────────────────

def pick_free_wg_port(ssh: "paramiko.SSHClient") -> int:
    """First free WireGuard listen-port in 12430-12466. Exits if none free."""
    _, out, _ = run_command(
        ssh,
        ':foreach i in=[/interface/wireguard/find] do={ :put [/interface/wireguard/get $i listen-port] }'
    )
    used = set()
    for line in out.splitlines():
        line = line.strip()
        if line.isdigit():
            used.add(int(line))
    print(f"  WG ports in use: {sorted(used) or 'none'}")
    for p in range(12430, 12467):
        if p not in used:
            return p
    sys.exit("ERROR: No free WireGuard listen-port in range 12430-12466")


def pick_free_dns_for_monitor(ssh: "paramiko.SSHClient") -> str:
    """Pick a non-RU public DNS not already used by system DNS, forwarding, or netwatch."""
    used: set[str] = set()

    # System DNS
    _, out, _ = run_command(ssh, ':put [/ip/dns/get servers]')
    for ip in out.replace(",", " ").split():
        used.add(ip.strip())

    # DNS forwarding servers
    _, out, _ = run_command(
        ssh,
        ':foreach i in=[/ip/dns/forward/find] do={ :put [/ip/dns/forward/get $i servers] }'
    )
    for ip in out.replace(",", " ").split():
        used.add(ip.strip())

    # Netwatch hosts (already used for monitoring)
    _, out, _ = run_command(
        ssh,
        ':foreach i in=[/tool/netwatch/find] do={ :put [/tool/netwatch/get $i host] }'
    )
    for ip in out.splitlines():
        used.add(ip.strip())

    print(f"  DNS/netwatch IPs in use: {sorted(ip for ip in used if ip)}")
    for candidate in DNS_CANDIDATES:
        if candidate not in used:
            return candidate
    sys.exit("ERROR: No free DNS candidate available for monitor route")


def setup_monitor(ssh: "paramiko.SSHClient", tag: str, wg_iface: str) -> None:
    """Enable existing Monitor route+netwatch, or create them if missing."""
    tag_upper = tag.upper()

    _, out, _ = run_command(
        ssh, f'/ip/route/print count-only where comment="Monitor-{tag_upper}"'
    )
    route_exists = out.strip() not in ("0", "")

    _, out, _ = run_command(
        ssh, f'/tool/netwatch/print count-only where comment="Monitor-{tag_upper}"'
    )
    netwatch_exists = out.strip() not in ("0", "")

    if route_exists and netwatch_exists:
        run_command(ssh, f'/ip/route/enable [find comment="Monitor-{tag_upper}"]')
        run_command(ssh, f'/tool/netwatch/enable [find comment="Monitor-{tag_upper}"]')
        print(f"  Enabled existing Monitor-{tag_upper} (route + netwatch)")
        return

    # At least one is missing — pick a free DNS to use
    dns_ip = pick_free_dns_for_monitor(ssh)
    print(f"  Selected monitor DNS IP: {dns_ip}")

    if route_exists:
        run_command(ssh, f'/ip/route/enable [find comment="Monitor-{tag_upper}"]')
        print(f"  Enabled existing route Monitor-{tag_upper}")
    else:
        run_command(
            ssh,
            f'/ip/route/add dst-address={dns_ip}/32 gateway={wg_iface} '
            f'distance=1 comment=Monitor-{tag_upper}'
        )
        print(f"  Added route: {dns_ip}/32 via {wg_iface} (Monitor-{tag_upper})")

    if netwatch_exists:
        run_command(ssh, f'/tool/netwatch/enable [find comment="Monitor-{tag_upper}"]')
        print(f"  Enabled existing netwatch Monitor-{tag_upper}")
    else:
        up   = f'/ip route enable [find comment=\\"Route-{tag_upper}\\"]'
        down = f'/ip route disable [find comment=\\"Route-{tag_upper}\\"]'
        run_command(
            ssh,
            f'/tool/netwatch/add host={dns_ip} interval=10s packet-count=5 '
            f'type=icmp thr-loss-count=4 timeout=5s '
            f'up-script="{up}" down-script="{down}" '
            f'comment=Monitor-{tag_upper}'
        )
        print(f"  Added netwatch: host={dns_ip} comment=Monitor-{tag_upper}")


def pick_free_veth_gateway(ssh: "paramiko.SSHClient") -> str:
    """First free veth gateway in 172.X.0.1 (X=20..36). Exits if none free."""
    _, out, _ = run_command(
        ssh,
        ':foreach i in=[/interface/veth/find] do={ :put [/interface/veth/get $i gateway] }'
    )
    used = set()
    for line in out.splitlines():
        line = line.strip()
        if line:
            used.add(line)
    print(f"  Veth gateways in use: {sorted(used) or 'none'}")
    for x in range(20, 37):
        gw = f"172.{x}.0.1"
        if gw not in used:
            return gw
    sys.exit("ERROR: No free veth gateway in range 172.20.0.1-172.36.0.1")


# ── RSC generation ─────────────────────────────────────────────────────────────

def generate_rsc(
    conf_path: str,
    tag: str,
    settings: dict,
    wg_listen_port: Optional[int] = None,
    veth_gateway: Optional[str] = None,
) -> str:
    sections = parse_conf(conf_path)
    iface = sections.get("Interface", {})
    peer = sections.get("Peer", {})

    effective_gateway = veth_gateway or settings.get("VETH_GATEWAY", "172.16.0.1")
    container_ip, container_cidr, veth_subnet = compute_veth(effective_gateway)
    effective_port = str(wg_listen_port) if wg_listen_port else settings.get("WG_LISTEN_PORT", "12430")
    keepalive = str(random.randint(10, 60))

    replacements = {
        "%%TAG%%":               tag,
        "%%TAG_UPPER%%":         tag.upper(),
        "%%PRIVATE_KEY%%":       iface["PrivateKey"],
        "%%CLIENT_ADDRESS%%":    iface["Address"],
        "%%SERVER_PUB%%":        peer["PublicKey"],
        "%%PRESHARED_KEY%%":     peer["PresharedKey"],
        "%%ENDPOINT%%":          peer["Endpoint"],
        "%%JC%%":                iface["Jc"],
        "%%JMIN%%":              iface["Jmin"],
        "%%JMAX%%":              iface["Jmax"],
        "%%S1%%":                iface["S1"],
        "%%S2%%":                iface["S2"],
        "%%H1%%":                iface["H1"],
        "%%H2%%":                iface["H2"],
        "%%H3%%":                iface["H3"],
        "%%H4%%":                iface["H4"],
        "%%VETH_GATEWAY%%":      effective_gateway,
        "%%VETH_CONTAINER%%":    container_cidr,
        "%%VETH_CONTAINER_IP%%": container_ip,
        "%%WG_LISTEN_PORT%%":    effective_port,
        "%%WG_MTU%%":            "1360",
        "%%WG_KEEPALIVE%%":      keepalive,
        "%%WG_LIST%%":           settings.get("WG_LIST", "VPN"),
        "%%AWG_LISTEN_PORT%%":   "51820",
        "%%AWG_I1%%":            iface.get("I1") or settings.get("AWG_I1") or (
            r"<r 2><b 0x8580000100010000000004796162730679616e6465780272750000010001"
            r"c00c000100010000026d000457fa27d1>"
        ),
    }

    # Optional extra env vars: S3/S4 and I2-I5 if present and non-empty in conf
    optional_lines = []
    for key in ["S3", "S4"]:
        if iface.get(key):
            optional_lines.append(
                f'/container/envs/add list={tag}-env key=AWG_{key} value="{iface[key]}"'
            )
    for key in ["I2", "I3", "I4", "I5"]:
        val = iface.get(key, "").strip()
        if val:
            optional_lines.append(
                f'/container/envs/add list={tag}-env key=AWG_{key} value="{val}"'
            )
    replacements["%%OPTIONAL_ENV%%"] = "\n".join(optional_lines)

    rsc = RSC_TEMPLATE
    for placeholder, value in replacements.items():
        rsc = rsc.replace(placeholder, value)
    return rsc


# ── SSH helpers ────────────────────────────────────────────────────────────────

def ssh_connect(
    host: str, port: int, user: str,
    key_path: Optional[str], password: Optional[str],
) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = dict(
        hostname=host, port=port, username=user,
        timeout=10, allow_agent=False, look_for_keys=False,
    )
    if key_path:
        kwargs["key_filename"] = str(Path(key_path).expanduser())
        kwargs["look_for_keys"] = True
    if password:
        kwargs["password"] = password
    ssh.connect(**kwargs)
    return ssh


def run_command(ssh: paramiko.SSHClient, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdout.channel.settimeout(timeout)
    exit_status = stdout.channel.recv_exit_status()
    return exit_status, stdout.read().decode().strip(), stderr.read().decode().strip()


def run_import(ssh: paramiko.SSHClient, remote_file: str, timeout: int = 600) -> int:
    """Run /import and stream output live. Returns exit status."""
    print(f"  Running /import {remote_file} ...")
    print("  (May take several minutes if container image needs to download)")
    stdin, stdout, stderr = ssh.exec_command(f'/import file-name="{remote_file}"')
    stdout.channel.settimeout(timeout)
    for line in stdout:
        print(f"  | {line.rstrip()}")
    return stdout.channel.recv_exit_status()


# ── Apply via SSH ──────────────────────────────────────────────────────────────

def apply_via_ssh(
    host: str, port: int, user: str,
    key_path: Optional[str], password: Optional[str],
    tag: str, conf_path: str, settings: dict,
    output_path: Optional[str] = None,
) -> None:
    remote_file = f"{tag}-install.rsc"
    uninstall_script = f"{tag}-uninstall"

    print(f"Connecting to {user}@{host}:{port} ...")
    ssh = ssh_connect(host, port, user, key_path, password)

    try:
        # 1. Check if this is a fresh install (no uninstall script exists yet)
        status, out, _ = run_command(
            ssh, f'/system/script/print count-only where name="{uninstall_script}"'
        )
        is_fresh_install = out.strip() in ("0", "")

        if not is_fresh_install:
            print(f"  Running {uninstall_script} ...")
            status, out, err = run_command(
                ssh, f'/system/script/run "{uninstall_script}"', timeout=90
            )
            if status != 0:
                print(f"  WARNING: uninstall returned {status}: {err or out}")
            else:
                print("  Uninstall complete.")
            time.sleep(3)
        else:
            print(f"  No existing {uninstall_script} — fresh install, will add monitor route + netwatch.")

        # 2. Query router for free resources, then generate script
        print("  Querying router for free WG port and veth gateway ...")
        free_port = pick_free_wg_port(ssh)
        free_gateway = pick_free_veth_gateway(ssh)
        print(f"  Selected WG port: {free_port}, veth gateway: {free_gateway}")

        rsc_content = generate_rsc(
            conf_path, tag, settings,
            wg_listen_port=free_port,
            veth_gateway=free_gateway,
        )

        if output_path:
            Path(output_path).write_text(rsc_content)
            print(f"  Generated script saved to {output_path}")

        # 3. Upload .rsc via SFTP
        print(f"  Uploading {remote_file} via SFTP ...")
        sftp = ssh.open_sftp()
        with sftp.open(remote_file, "w") as f:
            f.write(rsc_content)
        sftp.close()
        print("  Upload complete.")

        # 4. Import and execute the script on the router
        exit_status = run_import(ssh, remote_file)
        if exit_status != 0:
            print(f"  ERROR: /import exited with status {exit_status}")
            sys.exit(1)

        # 5. Clean up uploaded file
        run_command(ssh, f'/file/remove [find where name="{remote_file}"]')

        # 6. Enable or create monitor route + netwatch
        print("  Setting up monitor route and netwatch ...")
        setup_monitor(ssh, tag, f"wg-{tag}")

        print("Done.")

    finally:
        ssh.close()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate and apply AmneziaWG RouterOS script from .conf"
    )
    parser.add_argument("conf", help="Path to .conf file")
    parser.add_argument("tag", help="Instance tag, e.g. awg-de")
    parser.add_argument("--env", default=".env", help="Path to .env file (default: .env)")
    parser.add_argument("--output", help="Also write generated .rsc to this file")
    parser.add_argument("--dry-run", action="store_true", help="Print generated script, no SSH")
    parser.add_argument("--generate-only", action="store_true", help="Write .rsc file, skip SSH")
    # Web UI overrides (bypass .env)
    parser.add_argument("--host", dest="ssh_host", help="MikroTik host (overrides .env SSH_HOST)")
    parser.add_argument("--port", dest="ssh_port", help="SSH port (overrides .env SSH_PORT)")
    parser.add_argument("--user", dest="ssh_user", help="SSH user (overrides .env SSH_USER)")
    parser.add_argument("--password", dest="ssh_password", help="SSH password (overrides .env SSH_PASSWORD)")
    args = parser.parse_args()

    env = dotenv_values(args.env) if not args.ssh_host else {}

    host     = args.ssh_host     or env.get("SSH_HOST", "")
    port     = int(args.ssh_port or env.get("SSH_PORT", "22"))
    user     = args.ssh_user     or env.get("SSH_USER", "admin")
    key_path = None if args.ssh_host else (env.get("SSH_KEY") or None)
    password = args.ssh_password or env.get("SSH_PASSWORD") or None

    if args.dry_run or args.generate_only:
        # No SSH available — use .env values as-is
        rsc = generate_rsc(args.conf, args.tag, env)
        if args.output:
            Path(args.output).write_text(rsc)
            print(f"Written to {args.output}")
        if args.dry_run:
            print(rsc)
        elif not args.output:
            print(rsc)
        return

    if not host:
        sys.exit("SSH_HOST is not set in .env")

    apply_via_ssh(host, port, user, key_path, password, args.tag, args.conf, env, output_path=args.output)


if __name__ == "__main__":
    main()
