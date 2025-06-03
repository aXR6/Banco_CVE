import os
import sys
import types
sys.modules.setdefault("ijson", types.ModuleType("ijson"))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from parser import parse_item

sample_item = {
    "cve": {
        "CVE_data_meta": {"ID": "CVE-1234-0001"},
        "description": {"description_data": [{"value": "Desc\nline"}]}
    },
    "publishedDate": "2024-01-02T00:00Z",
    "configurations": {
        "nodes": [
            {"cpe_match": [
                {"cpe23Uri": "cpe:2.3:a:vendor:product:1.0"},
                {"cpe23Uri": "cpe:2.3:o:vendor:os:1.0"}
            ]}
        ]
    }
}

def test_parse_item():
    result = parse_item(sample_item)
    assert result == (
        "CVE-1234-0001",
        "2024-01-02T00:00Z",
        "Desc line",
        "cpe:2.3:a:vendor:product:1.0; cpe:2.3:o:vendor:os:1.0",
        "cpe:2.3:o:vendor:os:1.0",
    )


