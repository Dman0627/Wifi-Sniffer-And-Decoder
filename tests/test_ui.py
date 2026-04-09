from __future__ import annotations

from typing import Iterable

import pytest

from wifi_pipeline import ui


def _iter_inputs(values: Iterable[str]):
    iterator = iter(values)

    def _reader(_prompt: str) -> str:
        return next(iterator)

    return _reader


def test_banner_prints_product_heading(capsys) -> None:
    ui.banner()

    output = capsys.readouterr().out

    assert "WIFI STREAM PIPELINE v2.0" in output
    assert "Native Windows capture, flow extraction, analysis" in output


def test_section_prints_title_with_rule(capsys) -> None:
    ui.section("Capture")

    output = capsys.readouterr().out

    assert "-- Capture" in output
    assert "----" in output


def test_ask_returns_trimmed_input(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "  custom value  ")

    assert ui.ask("Value", default="fallback") == "custom value"


def test_ask_returns_default_on_blank_input(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "   ")

    assert ui.ask("Value", default="fallback") == "fallback"


def test_ask_uses_getpass_for_secret(monkeypatch) -> None:
    monkeypatch.setattr(ui, "getpass", lambda _prompt: "  secret-value  ")

    assert ui.ask("Password", default="fallback", secret=True) == "secret-value"


def test_ask_returns_default_on_interrupt(monkeypatch, capsys) -> None:
    def _raise_interrupt(_prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _raise_interrupt)

    assert ui.ask("Value", default="fallback") == "fallback"
    assert capsys.readouterr().out.endswith("\n")


def test_ask_int_returns_default_and_warns_on_invalid_integer(monkeypatch) -> None:
    warnings: list[str] = []

    monkeypatch.setattr(ui, "ask", lambda _prompt, _default=None, secret=False: "not-a-number")
    monkeypatch.setattr(ui, "warn", warnings.append)

    assert ui.ask_int("Threads", 4) == 4
    assert warnings == ["Invalid integer: 'not-a-number'. Keeping 4."]


def test_confirm_honors_blank_default(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "   ")

    assert ui.confirm("Continue?", default=False) is False


def test_confirm_accepts_yes_prefix(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "Yes")

    assert ui.confirm("Continue?", default=False) is True


def test_confirm_returns_default_on_interrupt(monkeypatch, capsys) -> None:
    def _raise_interrupt(_prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_interrupt)

    assert ui.confirm("Continue?", default=True) is True
    assert capsys.readouterr().out.endswith("\n")


def test_choose_returns_default_on_invalid_text(monkeypatch, capsys) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "invalid")

    selected = ui.choose("Pick one", ("alpha", "beta", "gamma"), default=1)

    output = capsys.readouterr().out

    assert selected == 1
    assert "[1] alpha" in output
    assert "[2] beta" in output
    assert "[3] gamma" in output


def test_choose_clamps_out_of_range_selection(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "99")

    assert ui.choose("Pick one", ("alpha", "beta", "gamma"), default=0) == 2


def test_choose_returns_default_on_interrupt(monkeypatch, capsys) -> None:
    def _raise_interrupt(_prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _raise_interrupt)

    assert ui.choose("Pick one", ("alpha", "beta"), default=0) == 0
    assert capsys.readouterr().out.endswith("\n")
