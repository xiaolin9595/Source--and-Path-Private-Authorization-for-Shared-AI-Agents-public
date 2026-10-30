#!/usr/bin/env python3
"""Small behavior check for the release scanner's personal-path rule."""

from sanitize_release import BAD_TEXT


def main() -> None:
    pattern = dict(BAD_TEXT)["personal filesystem path"]
    slash = b"/"
    for prefix in (b"Users", b"Volumes", b"home"):
        private_path = slash + prefix + slash + b"example-user" + slash + b"artifact"
        assert pattern.search(private_path), prefix
    for benign in (
        b"relative/path/to/artifact",
        slash + b"usr" + slash + b"local" + slash + b"bin",
        slash + b"home" + slash,
        slash + b"home" + slash + b"user without slash",
    ):
        assert not pattern.search(benign), benign
    print("sanitize personal-path behavior: PASS")


if __name__ == "__main__":
    main()
