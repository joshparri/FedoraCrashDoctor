#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from device_inventory import attribute_log_line, device_name_from_log, parse_lsblk_json


LSBLK = """{
  "blockdevices": [
    {"name":"nvme0n1","path":"/dev/nvme0n1","type":"disk","fstype":null,"mountpoints":[null],"model":"TOSHIBA","serial":"abc","rm":false,"tran":"nvme",
      "children":[{"name":"nvme0n1p3","path":"/dev/nvme0n1p3","type":"part","fstype":"btrfs","mountpoints":["/"],"model":null,"serial":null,"rm":false,"tran":null}]},
    {"name":"sda","path":"/dev/sda","type":"disk","fstype":null,"mountpoints":[null],"model":"Cruzer Blade","serial":"usb1","rm":true,"tran":"usb",
      "children":[{"name":"sda1","path":"/dev/sda1","type":"part","fstype":"vfat","mountpoints":["/run/media/josh/USB"],"model":null,"serial":null,"rm":true,"tran":null}]}
  ]
}"""


class DeviceInventoryTests(unittest.TestCase):
    def test_device_name_from_log(self):
        self.assertEqual(device_name_from_log("Buffer I/O error on dev sda1, logical block 1"), "sda1")
        self.assertEqual(device_name_from_log("BTRFS warning (device nvme0n1p3): read error"), "nvme0n1p3")

    def test_attributes_external_usb_partition(self):
        inventory = parse_lsblk_json(LSBLK)
        attr = attribute_log_line("Buffer I/O error on dev sda1, logical block 1", inventory)
        self.assertTrue(attr["known"])
        self.assertEqual(attr["transport"], "usb")
        self.assertFalse(attr["system_disk"])

    def test_attributes_internal_system_disk(self):
        inventory = parse_lsblk_json(LSBLK)
        attr = attribute_log_line("BTRFS warning (device nvme0n1p3): read error", inventory)
        self.assertTrue(attr["known"])
        self.assertTrue(attr["system_disk"])


if __name__ == "__main__":
    unittest.main()
