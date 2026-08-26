#!/usr/bin/env python3
"""Reusable block-device attribution helpers."""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass
class DeviceInfo:
    kernel_name: str
    path: str
    type: str
    fstype: str = ""
    mountpoints: list[str] | None = None
    model: str = ""
    serial: str = ""
    transport: str = ""
    parent: str = ""
    removable: bool = False
    usb_vidpid: str = ""
    internal: bool = False
    system_disk: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _flatten_lsblk(
    node: dict[str, Any],
    parent: str = "",
    parent_transport: str = "",
    parent_removable: bool = False,
) -> list[DeviceInfo]:
    name = str(node.get("name") or "")
    tran = str(node.get("tran") or "") or parent_transport
    removable = str(node.get("rm") or "0") in {"1", "true", "True"} or parent_removable
    mountpoints = node.get("mountpoints") or []
    if isinstance(mountpoints, str):
        mountpoints = [mountpoints]
    info = DeviceInfo(
        kernel_name=name,
        path=str(node.get("path") or f"/dev/{name}"),
        type=str(node.get("type") or ""),
        fstype=str(node.get("fstype") or ""),
        mountpoints=[str(item) for item in mountpoints if item],
        model=str(node.get("model") or "").strip(),
        serial=str(node.get("serial") or "").strip(),
        transport=tran,
        parent=parent,
        removable=removable,
        internal=tran not in {"usb"} and not removable,
        system_disk="/" in [str(item) for item in mountpoints if item],
    )
    children = []
    for child in node.get("children") or []:
        children.extend(_flatten_lsblk(child, name, tran, removable))
    if any(child.system_disk for child in children):
        info.system_disk = True
    return [info, *children]


def parse_lsblk_json(text: str) -> dict[str, DeviceInfo]:
    data = json.loads(text)
    devices: dict[str, DeviceInfo] = {}
    for node in data.get("blockdevices") or []:
        for info in _flatten_lsblk(node):
            devices[info.kernel_name] = info
            devices[Path(info.path).name] = info
    return devices


def collect_lsblk_inventory() -> dict[str, DeviceInfo]:
    proc = subprocess.run(
        ["lsblk", "-J", "-e7", "-o", "NAME,PATH,TYPE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL,RM,TRAN"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"},
    )
    if proc.returncode != 0:
        return {}
    return parse_lsblk_json(proc.stdout)


def device_name_from_log(line: str) -> str:
    patterns = [
        r"\bdev\s+([a-z]+[a-z0-9]*(?:p?\d+)?)\b",
        r"\((?:device\s+)?([a-z]+[a-z0-9]*(?:p?\d+)?)\)",
        r"\b(/dev/[a-z]+[a-z0-9]*(?:p?\d+)?)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, line, re.I)
        if match:
            return os.path.basename(match.group(1))
    return ""


def attribute_log_line(line: str, inventory: dict[str, DeviceInfo]) -> dict[str, Any] | None:
    name = device_name_from_log(line)
    if not name:
        return None
    info = inventory.get(name)
    if not info and re.match(r"sd[a-z]\d+$", name):
        info = inventory.get(re.sub(r"\d+$", "", name))
    if not info and re.match(r"nvme\d+n\d+p\d+$", name):
        info = inventory.get(re.sub(r"p\d+$", "", name))
    if not info:
        return {"kernel_name": name, "known": False}
    result = info.to_dict()
    result["known"] = True
    return result
