import pytest
import collector
import shutil

def test_collector_coredumps_json_task_is_bounded():
    # Ordinary quick scan gets built
    tasks = collector.build_tasks("quick")
    
    task = next((t for t in tasks if t.key == "coredumps_json"), None)
    assert task is not None
    
    cmd = task.command
    assert "--output-fields" in " ".join(cmd)
    
    # Check that we explicitly exclude unbounded COREDUMP 
    assert "COREDUMP" not in "".join(cmd) or "COREDUMP_PID" in "".join(cmd)
    assert "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,COREDUMP_PID,COREDUMP_UID,COREDUMP_GID,COREDUMP_SIGNAL,COREDUMP_SIGNAL_NAME,COREDUMP_EXE,_EXE,COREDUMP_CMDLINE,COREDUMP_COMM,COREDUMP_UNIT,_SYSTEMD_UNIT,COREDUMP_USER_UNIT,_HOSTNAME,COREDUMP_FILENAME" in " ".join(cmd)
