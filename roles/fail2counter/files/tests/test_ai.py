"""Behaviour tests for the refactored ``ai`` module."""

import ai


def _make_index() -> ai.ExploitIndex:
    """Build an ExploitIndex with a fixed in-memory module/detail set."""
    index = ai.ExploitIndex.__new__(ai.ExploitIndex)
    index.modules = [
        "exploit/linux/ssh/some_ssh_exploit",
        "exploit/multi/http/some_http_exploit",
        "exploit/windows/smb/some_smb_exploit",
    ]
    index.details = {
        "exploit/linux/ssh/some_ssh_exploit": "ssh details",
    }
    return index


def test_select_modules_matches_services() -> None:
    """Only modules whose platform and category match are selected."""
    index = _make_index()
    services = [{"service_name": "ssh", "product": "OpenSSH", "version": "8.0"}]
    selected = index.select_modules(services)
    assert "exploit/linux/ssh/some_ssh_exploit" in selected
    assert "exploit/windows/smb/some_smb_exploit" not in selected


def test_select_modules_empty_without_match() -> None:
    """No categories means no selected modules."""
    index = _make_index()
    assert not index.select_modules([{"service_name": "unknown"}])


def test_format_modules_falls_back_to_all_when_empty() -> None:
    """An empty filtered list yields the full module list."""
    index = _make_index()
    assert index.format_modules([]) == "\n".join(index.modules)


def test_format_modules_includes_details() -> None:
    """A module with details is rendered as a titled block."""
    index = _make_index()
    out = index.format_modules(["exploit/linux/ssh/some_ssh_exploit"])
    assert "===== exploit/linux/ssh/some_ssh_exploit =====" in out
    assert "ssh details" in out


def test_system_prompt_is_unchanged() -> None:
    """The system prompt embeds the module list with the exact wording."""
    prompt = ai.build_system_prompt("MODULE_LIST")
    assert prompt.startswith("You are a cybersecurity expert")
    assert "MODULE_LIST" in prompt
    assert prompt.endswith("set RPORT 80\nrun\n")
    assert "IMPORTANT RULES:" in prompt


def test_parse_ai_response_builds_exploits() -> None:
    """A two-block response parses into two validated exploits."""
    response = (
        "use exploit/linux/ssh/some_ssh_exploit\n"
        "set RHOSTS 192.0.2.5\n"
        "set RPORT 22\n"
        "run\n"
        "use exploit/multi/http/some_http_exploit\n"
        "set RHOSTS 192.0.2.5\n"
        "set RPORT 80\n"
        "run\n"
    )
    exploits = ai.parse_ai_response(response, "192.0.2.5")
    assert len(exploits) == 2
    assert exploits[0].module_path == "exploit/linux/ssh/some_ssh_exploit"
    assert exploits[0].rport == 22
    assert exploits[0].rhosts == "192.0.2.5"


def test_validate_module_adds_prefix() -> None:
    """Validation accepts a path with or without the exploit/ prefix."""
    known = {"exploit/linux/ssh/x"}
    assert ai.validate_module("exploit/linux/ssh/x", known)
    assert ai.validate_module("linux/ssh/x", known)
    assert not ai.validate_module("linux/ssh/unknown", known)


def test_write_msf_rc_appends_exit(tmp_path, monkeypatch) -> None:
    """A written RC file gains a trailing exit when absent."""
    monkeypatch.setattr(ai, "RC_DIR", str(tmp_path))
    exploit = ai.SuggestedExploit(
        module_path="exploit/linux/ssh/x",
        rhosts="192.0.2.9",
        rport=22,
        rc_content="use exploit/linux/ssh/x\nrun\n",
    )
    path = ai.write_msf_rc(exploit, 0)
    with open(path, encoding="utf-8") as handle:
        content = handle.read()
    assert content.endswith("exit\n")


def test_run_msf_handles_spawn_error(monkeypatch) -> None:
    """A failure to spawn msfconsole is reported as exit code -2."""

    def _boom(*_args, **_kwargs):
        raise OSError("no such binary")

    monkeypatch.setattr(ai.subprocess, "Popen", _boom)
    output, exit_code, duration = ai.run_msf("/nonexistent.rc")
    assert exit_code == -2
    assert "[ERROR]" in output
    assert duration >= 0.0
