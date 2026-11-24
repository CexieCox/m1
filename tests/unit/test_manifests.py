from __future__ import annotations

import csv

from utils.manifest_utils import write_csv


def test_csv_formula_neutralization_and_roundtrip(tmp_path) -> None:
    path = tmp_path / "cells.csv"
    rows = [{"value": "=1+1", "other": "plain", "list": ["a", "b"]}, {"value": "-2", "other": "@cmd", "list": []}]
    assert write_csv(path, ["value", "other", "list"], rows) == 2
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    parsed = list(csv.DictReader(path.open(encoding="utf-8-sig", newline="")))
    assert parsed[0]["value"] == "'=1+1"
    assert parsed[1]["value"] == "'-2"
    assert parsed[1]["other"] == "'@cmd"
    assert parsed[0]["list"] == '["a", "b"]'
