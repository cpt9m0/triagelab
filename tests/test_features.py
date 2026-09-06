from triagelab import features


def test_entropy_of_uniform_bytes_is_zero():
    assert features.shannon_entropy(b"AAAAAAAA") == 0.0


def test_entropy_of_empty_input_is_zero():
    assert features.shannon_entropy(b"") == 0.0


def test_entropy_of_all_byte_values_is_eight():
    assert round(features.shannon_entropy(bytes(range(256))), 6) == 8.0


def test_printable_ratio_counts_ascii_only():
    assert features.printable_ratio(b"abcd") == 1.0
    assert features.printable_ratio(b"\x00\x00ab") == 0.5


def test_extract_strings_respects_minimum_length():
    data = b"ab\x00CreateRemoteThread\x00cd"
    found = features.extract_strings(data, min_len=5)
    assert "CreateRemoteThread" in found
    assert "ab" not in found


def test_extract_reads_file_and_hashes_it(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"GetUserName and some padding text")
    result = features.extract(target)
    assert result.name == "sample.bin"
    assert result.size_bytes == 33
    assert len(result.sha256) == 64
    assert "GetUserName and some padding text" in result.strings
