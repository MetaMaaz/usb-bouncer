import tomllib
from pathlib import Path

import usb_bouncer


def test_version_is_exposed_and_matches_the_package_metadata():
    # the version lives in two files; the release workflow tags from one of them
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert usb_bouncer.__version__ == declared == "1.0.0"
