import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
scripts = sorted(glob.glob(os.path.join(HERE, "t[0-9][0-9]_*.py")))

passed, failed = [], []
for script in scripts:
    name = os.path.basename(script)
    result = subprocess.run([sys.executable, script], cwd=HERE,
                            capture_output=True, text=True)
    tag = name.split("_")[0].upper()
    if result.returncode == 0:
        passed.append(tag)
        print(f"[OK]   {tag} {name}")
    else:
        failed.append(tag)
        print(f"[FAIL] {tag} {name}")
        print(result.stdout[-500:])

print(f"\n{len(passed)}/{len(scripts)} test case PASSED: {' '.join(passed)}")
if failed:
    print(f"FAILED: {' '.join(failed)}")
    sys.exit(1)
