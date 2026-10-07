from __future__ import annotations

import pytest

from unpack.utils.apk import validate_package_name


class TestValidatePackageName:
    def test_valid_name(self):
        assert validate_package_name("com.example.app") == "com.example.app"

    def test_valid_with_underscore(self):
        assert validate_package_name("com.example.my_app") == "com.example.my_app"

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError):
            validate_package_name("com.example;rm -rf /")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError):
            validate_package_name("com.example`reboot`")

    def test_rejects_dollar(self):
        with pytest.raises(ValueError):
            validate_package_name("com.$(id).app")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_package_name("")

    def test_rejects_single_segment(self):
        with pytest.raises(ValueError):
            validate_package_name("singleword")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            validate_package_name("a" * 256)

    def test_rejects_none(self):
        with pytest.raises(ValueError):
            validate_package_name(None)  # type: ignore[arg-type]

    def test_rejects_pipe_and_ampersand(self):
        with pytest.raises(ValueError):
            validate_package_name("com.example|cat /data|app")
        with pytest.raises(ValueError):
            validate_package_name("com.example&&reboot&&app")

    def test_rejects_space(self):
        with pytest.raises(ValueError):
            validate_package_name("com.example app")

    def test_rejects_leading_dot_segment(self):
        with pytest.raises(ValueError):
            validate_package_name("com..example")

    def test_accepts_many_segments(self):
        assert validate_package_name("com.example.sub.pkg.name") == "com.example.sub.pkg.name"

    def test_accepts_max_length_boundary(self):
        # Exactly 255 chars: four 63-char segments joined by 3 dots.
        label = "a" * 63
        name = ".".join([label] * 4)
        assert len(name) == 255
        assert validate_package_name(name) == name

    def test_rejects_over_max_length_boundary(self):
        label = "a" * 63
        name = ".".join([label] * 4) + "x"
        assert len(name) == 256
        with pytest.raises(ValueError):
            validate_package_name(name)
