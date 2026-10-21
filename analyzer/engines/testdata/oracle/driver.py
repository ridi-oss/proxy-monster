import sys, os, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe

cases = json.load(sys.stdin)
out = [probe.probe_json(c["sql"], c["dialect"], json.dumps(c["schema"])) for c in cases]
json.dump(out, sys.stdout)
