from s2_dfa.checker import safe_output

def test_safe_output_trivial(tmp_path):
    dfa = tmp_path / "dfa.json"
    dfa.write_text('{"start":"q0","accept":["q1"],"transitions":{"q0":{"A":"q1"},"q1":{}}}')
    assert safe_output("A", str(dfa), bad_substrings=["BBB"])
    assert not safe_output("B", str(dfa), bad_substrings=[])

def test_substring_blocking():
    # Create minimal accepting DFA
    import tempfile, json
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({
            "start": "q0",
            "accept": ["q0"],
            "transitions": {"q0": {}}
        }, f)
        dfa_path = f.name
    
    # Should block if substring is found
    assert not safe_output("secret123", dfa_path, bad_substrings=["secret"])
    assert safe_output("safe", dfa_path, bad_substrings=["secret"])
