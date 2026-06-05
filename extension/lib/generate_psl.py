#!/usr/bin/env python3
"""Generate lib/psl-data.js from the Public Suffix List.

Downloads publicsuffix.org's list, strips comments/blank lines, and emits a
plain JS module exporting the rules as a newline-joined string. This avoids a
runtime fetch and any build step — psl.js imports it directly.

Run: python3 generate_psl.py
"""
import os
import urllib.request

URL = "https://publicsuffix.org/list/public_suffix_list.dat"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "psl-data.js")


def main():
    with urllib.request.urlopen(URL, timeout=30) as r:
        text = r.read().decode("utf-8")

    rules = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        # Rules are case-insensitive; the list is ASCII/punycode for our use.
        rules.append(s.lower())

    body = "\n".join(rules)
    assert "`" not in body, "backtick in PSL would break the template literal"

    js = (
        "// AUTO-GENERATED from publicsuffix.org/list/public_suffix_list.dat\n"
        "// Do not edit by hand. Regenerate with: python3 generate_psl.py\n"
        f"// {len(rules)} rules.\n"
        "export const PSL_RULES = `" + body + "`;\n"
    )
    with open(OUT, "w") as f:
        f.write(js)
    print(f"wrote {OUT} ({len(rules)} rules, {len(js)} bytes)")


if __name__ == "__main__":
    main()
