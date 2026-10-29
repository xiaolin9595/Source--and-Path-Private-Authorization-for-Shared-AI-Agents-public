#!/usr/bin/env python3
"""Independently evaluate the author's Sage permutation using Python integers.
No Sage/Rust dependencies; checks the committed reference and parameter digest.
The expected outputs are computed from the author algorithm, not a published KAT.
"""
import ast
import hashlib
import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
source = (HERE / "hrada_poseidon_reference.sage").read_bytes()
text = source.decode()
prime = int(re.search(r"^prime = (0x[0-9a-f]+)$", text, re.M)[1], 16)
round_constants = [int(v, 16) for v in ast.literal_eval(re.search(r"^round_constants = (\[.*\])$", text, re.M)[1])]
mds = [[int(v, 16) for v in row] for row in ast.literal_eval(re.search(r"^MDS_matrix = (\[.*\])$", text, re.M)[1])]
assert len(round_constants) == 195 and len(mds) == 3
state = [0, 1, 2]
for round_index in range(65):
    state = [(state[i] + round_constants[round_index * 3 + i]) % prime for i in range(3)]
    state = [pow(value, 5, prime) if round_index < 4 or round_index >= 61 or i == 0 else value for i, value in enumerate(state)]
    state = [sum(mds[i][j] * state[j] for j in range(3)) % prime for i in range(3)]
parameter_bytes = b"".join(value.to_bytes(32, "little") for value in round_constants + sum(mds, []))
result = {"source_url": "https://extgit.iaik.tugraz.at/krypto/hadeshash/-/raw/master/code/poseidonperm_x5_255_3.sage", "source_sha256": hashlib.sha256(source).hexdigest(), "parameter_blake2s": hashlib.blake2s(parameter_bytes).hexdigest(), "input": [0, 1, 2], "output_decimal": [str(value) for value in state], "method": "Python integer evaluation of author Sage round function; not an author-published literal KAT"}
rust = (HERE / "hrada_poseidon_parameters.rs").read_text()
expected = ast.literal_eval(re.search(r"REFERENCE_012: \[&str; 3\] = (\[.*?\]);", rust, re.S)[1])
assert result["output_decimal"] == expected
assert result["source_sha256"] in rust and result["parameter_blake2s"] in rust
print(json.dumps(result, indent=2))
