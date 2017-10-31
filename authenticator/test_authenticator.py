from authenticator import get_profile
import pytest
import os


def test_get_profile(tmpdir):
	p = tmpdir.mkdir("sub").join("hello.txt")
	with pytest.raises (SystemExit) as excinfo:
		print(get_profile(p, "pmd-hp"))
		assert "Error" in get_profile(p, "pmd-hp")   
	p.write("[pmd-hp]")
	assert get_profile(p, "pmd-hp") == "pmd-hp"
	#assert get_profile(p, "pmd-hpa") != "pmd-hp"
	with pytest.raises (SystemExit) as excinfo:
		assert "Error" in get_profile("credentials", "pmd-hp")
	with pytest.raises (SystemExit) as excinfo:
		assert "Error" in get_profile(p, "pmd-hpa")
