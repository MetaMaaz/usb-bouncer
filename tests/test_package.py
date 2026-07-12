import usb_bouncer


def test_version_is_exposed():
    assert usb_bouncer.__version__ == "0.1.0"
