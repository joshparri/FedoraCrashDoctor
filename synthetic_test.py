import time
from pathlib import Path
from safe_mitigation import StabilityController
import subprocess
import json

def _mem_sample(avail_mb, total_mb=16000, swap_used=0, some_psi=0, io_full=0, hb_age=0):
    return {
        "ts": "2026-08-27T10:30:00+10:00",
        "memory": {"mem_available_mb": avail_mb, "mem_total_mb": total_mb, "swap_used_mb": swap_used, "swap_total_mb": 8192},
        "psi_mem": {"some_avg10": some_psi},
        "psi_io": {"full_avg10": io_full},
        "desktop_heartbeat_age_s": hb_age,
        "kwin_ok": True,
        "plasmashell_ok": True,
        "processes": {"top_rss": [{"name": "chrome", "group": "Google Chrome", "rss_kb": 3_500_000}]}
    }

def run_tests():
    out_dir = Path("/run/user/1002/fedora-crash-doctor")
    out_dir.mkdir(exist_ok=True, parents=True)
    
    # We will simulate the canary by passing our uid/gid to the controller
    import os
    uid, gid = os.getuid(), os.getgid()
    Path("/tmp/fcd-test-owner.json").write_text(json.dumps({"uid": uid, "gid": gid}))
    
    controller = StabilityController(owner_config=Path("/tmp/fcd-test-owner.json"), out_dir=out_dir)
    
    print("Test A: Normal synthetic sample")
    res = controller.process_sample(_mem_sample(8000))
    print("Result:", res)
    
    print("\nTest B: Sustained warning samples")
    controller.process_sample(_mem_sample(1002, swap_used=6000, some_psi=15))
    res = controller.process_sample(_mem_sample(1002, swap_used=6000, some_psi=15))
    print("Result:", res)
    
    print("\nTest C: Critical escalation")
    res = controller.process_sample(_mem_sample(400, swap_used=8000, some_psi=25, io_full=25))
    print("Result:", res)
    
    print("\nTest D: Continued critical samples")
    res = controller.process_sample(_mem_sample(400, swap_used=8000, some_psi=25, io_full=25))
    print("Result:", res)
    
    print("\nTest E: Recovery")
    res1 = controller.process_sample(_mem_sample(8000))
    res2 = controller.process_sample(_mem_sample(8000))
    print("Result 1:", res1)
    print("Result 2:", res2)
    # Fully recover internal state (takes 5)
    for _ in range(3):
        controller.process_sample(_mem_sample(8000))
        
    print("\nTest F: Second independent pressure episode")
    controller.process_sample(_mem_sample(1002, swap_used=6000, some_psi=15))
    res = controller.process_sample(_mem_sample(1002, swap_used=6000, some_psi=15))
    print("Result:", res)
    
if __name__ == "__main__":
    run_tests()
