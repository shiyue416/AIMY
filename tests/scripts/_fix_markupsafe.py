"""Bulk fix: add markupsafe<3.0 to all Flask/Jinja2 requirements.txt files."""
from pathlib import Path
import re

bench = Path(r"C:\Users\PC\Desktop\validation-benchmarks\benchmarks")
fixed = 0
skipped = 0

for req_file in sorted(bench.glob("**/requirements*.txt")):
    content = req_file.read_text()
    has_flask = bool(re.search(r"(?i)flask|jinja", content))
    has_markupsafe_pin = bool(re.search(r"(?i)markupsafe\s*[<>=]", content))

    if has_flask and not has_markupsafe_pin:
        new_content = content.rstrip() + "\nmarkupsafe<3.0\n"
        req_file.write_text(new_content)
        fixed += 1
        print("FIX: " + req_file.parent.parent.name + "/" + req_file.parent.name)
    else:
        skipped += 1

print("\nFixed: %d files" % fixed)
print("Skipped: %d files (already pinned or no Flask)" % skipped)
