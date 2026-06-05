import os
import re
import sys
import subprocess
import tempfile
from pathlib import Path
from functools import wraps

import paramiko
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify,
)

APP_DIR = Path(__file__).parent
PROJECT_DIR = APP_DIR.parent

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))


# ── Auth ───────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "host" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


# ── SSH helpers ────────────────────────────────────────────────────────────────

def get_ssh():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        session["host"],
        port=int(session.get("ssh_port", 22)),
        username=session["user"],
        password=session["password"],
        allow_agent=False,
        look_for_keys=False,
        timeout=10,
    )
    return ssh


def run_cmd(ssh, cmd: str, timeout: int = 30):
    _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    status = stdout.channel.recv_exit_status()
    return status, out, err


def _p(parts, n, default=""):
    return parts[n] if len(parts) > n else default


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        host     = request.form.get("host", "").strip()
        port     = request.form.get("port", "22").strip() or "22"
        user     = request.form.get("user", "").strip()
        password = request.form.get("password", "")
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                host, port=int(port), username=user, password=password,
                allow_agent=False, look_for_keys=False, timeout=10,
            )
            ssh.close()
            session.clear()
            session.update({"host": host, "ssh_port": port, "user": user, "password": password})
            return redirect(url_for("dashboard"))
        except Exception as e:
            error = str(e)
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", host=session["host"])


# ── Netwatch ───────────────────────────────────────────────────────────────────

@app.route("/api/netwatch")
@login_required
def api_netwatch():
    try:
        ssh = get_ssh()
        cmd = (
            ':foreach i in=[/tool/netwatch/find] do={'
            ':local h [/tool/netwatch/get $i host];'
            ':local c "";:local s "";:local t "";:local iv "";:local dis "";'
            ':local to "";:local pc "";:local tlc "";:local ds "";:local tm "";:local ta "";:local ra "";'
            ':do {:set c [/tool/netwatch/get $i comment]} on-error={};'
            ':set s [:tostr [/tool/netwatch/get $i status]];'
            ':set t [:tostr [/tool/netwatch/get $i type]];'
            ':set iv [:tostr [/tool/netwatch/get $i interval]];'
            ':set dis [:tostr [/tool/netwatch/get $i disabled]];'
            ':do {:set to [:tostr [/tool/netwatch/get $i timeout]]} on-error={};'
            ':do {:set pc [:tostr [/tool/netwatch/get $i packet-count]]} on-error={};'
            ':do {:set tlc [:tostr [/tool/netwatch/get $i thr-loss-count]]} on-error={};'
            ':do {:set ds [:tostr [/tool/netwatch/get $i dns-server]]} on-error={};'
            ':do {:set tm [:tostr [/tool/netwatch/get $i thr-max]]} on-error={};'
            ':do {:set ta [:tostr [/tool/netwatch/get $i thr-avg]]} on-error={};'
            ':do {:set ra [:tostr [/tool/netwatch/get $i rtt-avg]]} on-error={};'
            ':put ($h."|".$c."|".$t."|".$s."|".$iv."|".$dis."|".$to."|".$pc."|".$tlc."|".$ds."|".$tm."|".$ta."|".$ra)'
            '}'
        )
        _, out, _ = run_cmd(ssh, cmd)
        ssh.close()

        entries = []
        for line in out.splitlines():
            pts = line.split("|")
            if len(pts) < 4:
                continue
            entries.append({
                "host":           _p(pts, 0),
                "comment":        _p(pts, 1),
                "type":           _p(pts, 2),
                "status":         _p(pts, 3),
                "interval":       _p(pts, 4),
                "disabled":       _p(pts, 5),
                "timeout":        _p(pts, 6),
                "packet_count":   _p(pts, 7),
                "thr_loss_count": _p(pts, 8),
                "dns_server":     _p(pts, 9),
                "thr_max":        _p(pts, 10),
                "thr_avg":        _p(pts, 11),
                "rtt_avg":        _p(pts, 12),
            })

        entries.sort(key=lambda e: (e["comment"] or e["host"]).lower())
        return jsonify({"ok": True, "data": entries})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/netwatch/update", methods=["POST"])
@login_required
def api_netwatch_update():
    data = request.get_json() or {}
    comment = (data.get("comment") or "").strip()
    if not comment:
        return jsonify({"ok": False, "error": "comment required"})

    # Regular fields — skip if empty
    regular_map = {
        "host":           "host",
        "type":           "type",
        "interval":       "interval",
        "timeout":        "timeout",
        "packet_count":   "packet-count",
        "thr_loss_count": "thr-loss-count",
        "dns_server":     "dns-server",
    }
    # Threshold fields — set to 0ms when explicitly cleared (empty string sent)
    threshold_map = {
        "thr_max": "thr-max",
        "thr_avg": "thr-avg",
    }
    ros_parts = []
    for key, ros_field in regular_map.items():
        v = (data.get(key) or "").strip()
        if v:
            ros_parts.append(f'{ros_field}={v}')
    for key, ros_field in threshold_map.items():
        if key in data:  # key was explicitly sent
            v = (data[key] or "").strip()
            ros_parts.append(f'{ros_field}={v}' if v else f'{ros_field}=0ms')

    if not ros_parts:
        return jsonify({"ok": False, "error": "no fields provided"})

    try:
        ssh = get_ssh()
        cmd = f'/tool/netwatch/set [find where comment="{comment}"] {" ".join(ros_parts)}'
        _, _, err = run_cmd(ssh, cmd)
        ssh.close()
        return jsonify({"ok": not bool(err), "error": err or None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/api/routes")
@login_required
def api_routes():
    try:
        ssh = get_ssh()
        cmd = (
            ':foreach i in=[/ip/route/find where routing-table~"vpn"] do={'
            ':local dst [/ip/route/get $i dst-address];'
            ':local gw "";'
            ':local rt [/ip/route/get $i routing-table];'
            ':local dist [/ip/route/get $i distance];'
            ':local act [:tostr [/ip/route/get $i active]];'
            ':local dis [:tostr [/ip/route/get $i disabled]];'
            ':local cmt "";'
            ':do {:set gw [/ip/route/get $i gateway]} on-error={};'
            ':do {:set cmt [/ip/route/get $i comment]} on-error={};'
            ':put ($dst."|".$gw."|".$rt."|".$dist."|".$act."|".$dis."|".$cmt)'
            '}'
        )
        _, out, _ = run_cmd(ssh, cmd)
        ssh.close()

        entries = []
        for line in out.splitlines():
            pts = line.split("|")
            if len(pts) < 4:
                continue
            table = _p(pts, 2)
            if table == "unvpn":
                continue
            try:
                dist_int = int(_p(pts, 3, "999"))
            except ValueError:
                dist_int = 999
            entries.append({
                "dst":          _p(pts, 0),
                "gateway":      _p(pts, 1),
                "table":        table,
                "distance":     _p(pts, 3),
                "distance_int": dist_int,
                "active":       _p(pts, 4),
                "disabled":     _p(pts, 5),
                "comment":      _p(pts, 6),
            })

        entries.sort(key=lambda r: (r["table"], r["distance_int"]))
        return jsonify({"ok": True, "data": entries})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/route/candidates")
@login_required
def api_route_candidates():
    table = request.args.get("table", "").strip()
    if not table:
        return jsonify({"ok": False, "error": "table required"})
    try:
        ssh = get_ssh()
        cmd_used = (
            f':foreach i in=[/ip/route/find where routing-table="{table}"] do={{'
            ':local gw "";'
            ':do {:set gw [/ip/route/get $i gateway]} on-error={};'
            ':if ($gw != "") do={ :put $gw }'
            '}'
        )
        _, out, _ = run_cmd(ssh, cmd_used)
        used = set(ln.strip() for ln in out.splitlines() if ln.strip())

        _, out, _ = run_cmd(
            ssh,
            ':foreach i in=[/interface/wireguard/find] do={ :put [/interface/wireguard/get $i name] }',
        )
        ssh.close()
        all_wg = [ln.strip() for ln in out.splitlines() if ln.strip()]
        candidates = [iface for iface in all_wg
                      if iface not in used and iface.startswith("wg-")]
        return jsonify({"ok": True, "data": candidates, "table": table})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/route/add", methods=["POST"])
@login_required
def api_route_add():
    data     = request.get_json() or {}
    gateway  = (data.get("gateway") or "").strip()
    table    = (data.get("table") or "").strip()
    distance = (data.get("distance") or "1").strip()
    comment  = (data.get("comment") or "").strip()
    dst      = (data.get("dst") or "0.0.0.0/0").strip()

    if not gateway or not table:
        return jsonify({"ok": False, "error": "gateway and table required"})
    try:
        ssh = get_ssh()
        cmd = (
            f'/ip/route/add dst-address={dst} gateway={gateway} '
            f'routing-table={table} distance={distance}'
        )
        if comment:
            cmd += f' comment="{comment}"'
        _, _, err = run_cmd(ssh, cmd)
        ssh.close()
        return jsonify({"ok": not bool(err), "error": err or None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/route/delete", methods=["POST"])
@login_required
def api_route_delete():
    data    = request.get_json() or {}
    comment = (data.get("comment") or "").strip()
    table   = (data.get("table") or "").strip()
    dst     = (data.get("dst") or "").strip()
    gateway = (data.get("gateway") or "").strip()

    if not table:
        return jsonify({"ok": False, "error": "table required"})
    try:
        ssh = get_ssh()
        if comment:
            selector = f'[find where comment="{comment}" and routing-table="{table}"]'
        elif dst and gateway:
            selector = f'[find where dst-address="{dst}" and gateway="{gateway}" and routing-table="{table}"]'
        elif dst:
            selector = f'[find where dst-address="{dst}" and routing-table="{table}"]'
        else:
            return jsonify({"ok": False, "error": "comment or dst required"})
        _, _, err = run_cmd(ssh, f'/ip/route/remove {selector}')
        ssh.close()
        return jsonify({"ok": not bool(err), "error": err or None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── Route bulk set-distances ──────────────────────────────────────────────────

@app.route("/api/route/set-distances", methods=["POST"])
@login_required
def api_route_set_distances():
    changes = (request.get_json() or {}).get("changes", [])
    if not changes:
        return jsonify({"ok": False, "error": "no changes"})
    try:
        ssh = get_ssh()
        errors = []
        for c in changes:
            comment  = (c.get("comment") or "").strip()
            table    = (c.get("table") or "").strip()
            distance = str(c.get("distance", "1"))
            dst      = (c.get("dst") or "").strip()
            gateway  = (c.get("gateway") or "").strip()
            if comment:
                sel = f'[find where comment="{comment}" and routing-table="{table}"]'
            elif dst and gateway:
                sel = f'[find where dst-address="{dst}" and gateway="{gateway}" and routing-table="{table}"]'
            else:
                continue
            _, _, err = run_cmd(ssh, f'/ip/route/set {sel} distance={distance}')
            if err:
                errors.append(err)
        ssh.close()
        return jsonify({"ok": not errors, "errors": errors})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── AWG scripts list & run ────────────────────────────────────────────────────

@app.route("/api/scripts")
@login_required
def api_scripts():
    try:
        ssh = get_ssh()
        cmd = (
            ':foreach i in=[/system/script/find where name~"awg-"] do={'
            ':local n [/system/script/get $i name];'
            ':local c "";'
            ':do {:set c [/system/script/get $i comment]} on-error={};'
            ':put ($n."|".$c)'
            '}'
        )
        _, out, _ = run_cmd(ssh, cmd)
        ssh.close()
        scripts = []
        for line in out.splitlines():
            pts = line.split("|")
            if pts[0].strip():
                scripts.append({"name": pts[0].strip(), "comment": _p(pts, 1).strip()})
        scripts.sort(key=lambda s: s["name"])
        return jsonify({"ok": True, "data": scripts})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/scripts/run", methods=["POST"])
@login_required
def api_scripts_run():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name or not name.startswith("awg-"):
        return jsonify({"ok": False, "error": "invalid script name"})
    try:
        ssh = get_ssh()
        _, out, err = run_cmd(ssh, f'/system/script/run [find where name="{name}"]', timeout=120)
        ssh.close()
        return jsonify({"ok": not bool(err), "output": out, "error": err or None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── Route optimizer (ping from MikroTik) ───────────────────────────────────────

@app.route("/api/optimize/ping")
@login_required
def api_optimize_ping():
    table = request.args.get("table", "").strip()
    if not table:
        return jsonify({"ok": False, "error": "table required"})
    try:
        ssh = get_ssh()

        # 1. Get all non-disabled routes in this table
        cmd = (
            f':foreach i in=[/ip/route/find where routing-table="{table}" disabled=no] do={{'
            ':local gw "";:local cmt "";:local dist "";:local dst "";'
            ':do {:set gw [/ip/route/get $i gateway]} on-error={};'
            ':do {:set cmt [/ip/route/get $i comment]} on-error={};'
            ':do {:set dst [/ip/route/get $i dst-address]} on-error={};'
            ':set dist [:tostr [/ip/route/get $i distance]];'
            ':if ($gw != "") do={ :put ($gw."|".$cmt."|".$dist."|".$dst) }'
            '}'
        )
        _, out, _ = run_cmd(ssh, cmd)

        routes = []
        for line in out.splitlines():
            pts = line.split("|")
            if pts and pts[0].strip():
                routes.append({
                    "gateway":  pts[0].strip(),
                    "comment":  _p(pts, 1).strip(),
                    "distance": _p(pts, 2).strip(),
                    "dst":      _p(pts, 3).strip(),
                    "table":    table,
                })

        results = []
        for r in routes:
            gw = r["gateway"]  # e.g. wg-awg-nl or 10.10.37.1%vault.tec
            # Derive monitor comment: strip wg- prefix if present
            if gw.startswith("wg-"):
                tag_upper = gw[3:].upper()
            else:
                # Use comment to find monitor (Route-XXX → Monitor-XXX)
                cmt = r["comment"]
                tag_upper = cmt.replace("Route-", "", 1).upper() if cmt.startswith("Route-") else ""
            monitor_comment = f"Monitor-{tag_upper}" if tag_upper else ""

            # Find netwatch entry for this route
            if not monitor_comment:
                results.append({**r, "ping_host": "", "avg_ms": None, "note": "no monitor"})
                continue
            cmd_nw = (
                f':local host "";:local nwtype "";:local ds "";'
                f':foreach i in=[/tool/netwatch/find where comment="{monitor_comment}"] do={{'
                f':set host [/tool/netwatch/get $i host];'
                f':set nwtype [:tostr [/tool/netwatch/get $i type]];'
                f':do {{:set ds [:tostr [/tool/netwatch/get $i dns-server]]}} on-error={{}};'
                f'}};:put ($host."|".$nwtype."|".$ds)'
            )
            _, nw_out, _ = run_cmd(ssh, cmd_nw)
            nw_pts = nw_out.strip().split("|")
            host    = nw_pts[0].strip() if nw_pts else ""
            nw_type = nw_pts[1].strip() if len(nw_pts) > 1 else "icmp"
            ds      = nw_pts[2].strip() if len(nw_pts) > 2 else ""

            if not host:
                results.append({**r, "ping_host": "", "avg_ms": None, "note": "no monitor"})
                continue

            # For dns type use dns-server IP; for icmp/simple use host
            ping_target = ds if (nw_type == "dns" and ds) else host

            # Ping 5 times from MikroTik
            _, ping_out, _ = run_cmd(ssh, f'/tool/ping address={ping_target} count=5', timeout=30)

            avg_ms = None
            for line in ping_out.splitlines():
                if "avg-rtt=" in line:
                    m = re.search(r'avg-rtt=(\d+(?:\.\d+)?)(ms|us|s)', line)
                    if m:
                        val, unit = float(m.group(1)), m.group(2)
                        avg_ms = val if unit == "ms" else (val / 1000 if unit == "us" else val * 1000)
                    break

            results.append({**r, "ping_host": ping_target, "avg_ms": avg_ms,
                             "note": ping_out.splitlines()[-1] if ping_out else ""})

        ssh.close()

        # Sort by avg_ms ascending (unreachable at end)
        results.sort(key=lambda x: (x["avg_ms"] is None, x["avg_ms"] or 0))
        for i, r in enumerate(results, 1):
            r["proposed_distance"] = i

        return jsonify({"ok": True, "data": results, "table": table})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── Address Lists & DNS Static FWD ────────────────────────────────────────────

def _parse_ros_id(id_str: str) -> int:
    """Parse RouterOS object ID like '*2A' to int (higher = newer)."""
    if id_str.startswith("*"):
        try:
            return int(id_str[1:], 16)
        except ValueError:
            pass
    return 0


@app.route("/api/addrlist")
@login_required
def api_addrlist():
    try:
        ssh = get_ssh()
        cmd = (
            ':foreach i in=[/ip/firewall/address-list/find where dynamic=no] do={'
            ':local addr "";:local lst "";:local ct "";:local cmt "";'
            ':do {:set addr [/ip/firewall/address-list/get $i address]} on-error={};'
            ':do {:set lst  [/ip/firewall/address-list/get $i list]}    on-error={};'
            ':do {:set ct   [:tostr [/ip/firewall/address-list/get $i creation-time]]} on-error={};'
            ':do {:set cmt  [/ip/firewall/address-list/get $i comment]} on-error={};'
            ':local rid [:tostr $i];'
            ':if ($lst = "hike" or $lst = "vpn" or $lst = "unvpn" or ($lst ~ "^vpn-")) do={'
            ':put ($addr."|".$lst."|".$ct."|".$rid."|".$cmt)'
            '}}'
        )
        _, out, _ = run_cmd(ssh, cmd)

        # Query DNS static FWD entries to detect per-list forward-to IP
        cmd_dns = (
            ':foreach i in=[/ip/dns/static/find where type=FWD] do={'
            ':local al "";:local fwd "";'
            ':do {:set al  [/ip/dns/static/get $i address-list]} on-error={};'
            ':do {:set fwd [/ip/dns/static/get $i forward-to]}   on-error={};'
            ':if ($al != "") do={ :put ($al."|".$fwd) }'
            '}'
        )
        _, dns_out, _ = run_cmd(ssh, cmd_dns)
        ssh.close()

        # Build fwd_by_list: most-common forward-to per list
        fwd_counts: dict = {}
        for line in dns_out.splitlines():
            if not line.strip():
                continue
            pts = line.split("|")
            lst_name = _p(pts, 0).strip()
            fwd_ip   = _p(pts, 1).strip()
            if lst_name and fwd_ip:
                fwd_counts.setdefault(lst_name, {})
                fwd_counts[lst_name][fwd_ip] = fwd_counts[lst_name].get(fwd_ip, 0) + 1
        fwd_by_list = {
            lst_name: max(counts, key=counts.get)
            for lst_name, counts in fwd_counts.items()
        }

        entries = []
        for line in out.splitlines():
            if not line.strip():
                continue
            pts = line.split("|")
            entries.append({
                "address":       _p(pts, 0).strip(),
                "list":          _p(pts, 1).strip(),
                "creation_time": _p(pts, 2).strip(),
                "_id":           _p(pts, 3).strip(),
                "comment":       _p(pts, 4).strip(),
            })

        # Group by list, sort each group newest→oldest by RouterOS ID
        groups: dict = {}
        for e in entries:
            groups.setdefault(e["list"], []).append(e)
        for grp in groups.values():
            grp.sort(key=lambda e: _parse_ros_id(e["_id"]), reverse=True)

        # Flatten: alphabetical list order, per-list newest first
        result = []
        for lst_name in sorted(groups.keys()):
            result.extend(groups[lst_name])

        for e in result:
            del e["_id"]  # internal only

        return jsonify({"ok": True, "data": result, "fwd_by_list": fwd_by_list})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/addrlist/add", methods=["POST"])
@login_required
def api_addrlist_add():
    data       = request.get_json() or {}
    addresses  = data.get("addresses") or []
    # Backwards compat: single address field
    if not addresses and data.get("address"):
        addresses = [data["address"]]
    addresses  = [a.strip() for a in addresses if str(a).strip()]
    lst        = (data.get("list")       or "").strip()
    forward_to = (data.get("forward_to") or "8.8.8.8").strip()
    if not addresses or not lst:
        return jsonify({"ok": False, "error": "address and list are required"})
    if not re.match(r'^(hike|vpn|unvpn|vpn-.+)$', lst):
        return jsonify({"ok": False, "error": f"invalid list name: {lst}"})
    try:
        ssh = get_ssh()
        errors = []
        dns_errors = []
        for address in addresses:
            _, _, err1 = run_cmd(ssh, f'/ip/firewall/address-list/add address="{address}" list="{lst}"')
            if err1:
                errors.append(f"{address}: {err1}")
                continue
            _, _, err2 = run_cmd(
                ssh,
                f'/ip/dns/static/add name="{address}" type=FWD'
                f' forward-to="{forward_to}" address-list="{lst}" match-subdomain=yes',
            )
            if err2:
                dns_errors.append(f"{address}: {err2}")
        ssh.close()
        if errors:
            return jsonify({"ok": False, "error": "; ".join(errors), "dns_errors": dns_errors})
        return jsonify({"ok": True, "count": len(addresses),
                        "dns_errors": dns_errors if dns_errors else None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/addrlist/delete", methods=["POST"])
@login_required
def api_addrlist_delete():
    data    = request.get_json() or {}
    address = (data.get("address") or "").strip()
    lst     = (data.get("list")    or "").strip()
    if not address or not lst:
        return jsonify({"ok": False, "error": "address and list are required"})
    try:
        ssh = get_ssh()
        _, _, err1 = run_cmd(
            ssh,
            f'/ip/firewall/address-list/remove [find where address="{address}" list="{lst}"]',
        )
        _, _, err2 = run_cmd(
            ssh,
            f'/ip/dns/static/remove [find where name="{address}" type=FWD address-list="{lst}"]',
        )
        ssh.close()
        return jsonify({"ok": not bool(err1), "error": err1 or None, "dns_error": err2 or None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ── Deploy ─────────────────────────────────────────────────────────────────────

@app.route("/deploy", methods=["POST"])
@login_required
def deploy():
    conf_file = request.files.get("conf")
    tag = request.form.get("tag", "").strip()

    if not conf_file or not conf_file.filename:
        return jsonify({"ok": False, "error": "No .conf file uploaded"})
    if not tag:
        return jsonify({"ok": False, "error": "Tag is required"})

    suffix = Path(conf_file.filename).suffix or ".conf"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="wb") as f:
        conf_file.save(f)
        tmp_conf = f.name

    try:
        result = subprocess.run(
            [
                sys.executable, str(PROJECT_DIR / "update_awg.py"),
                tmp_conf, tag,
                "--host",     session["host"],
                "--port",     session.get("ssh_port", "22"),
                "--user",     session["user"],
                "--password", session["password"],
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        output = result.stdout
        if result.stderr:
            output += "\n--- stderr ---\n" + result.stderr
        return jsonify({"ok": result.returncode == 0, "output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Deploy timed out (180s)"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    finally:
        Path(tmp_conf).unlink(missing_ok=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
