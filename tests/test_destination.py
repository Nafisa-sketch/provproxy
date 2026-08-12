from provproxy.config import PolicyFile, ServerBinding, ToolCapability
from provproxy.destination import extract_destination_candidates, is_destination_allowed, is_sensitive_source


def _policy():
    return PolicyFile(
        version="test",
        server_bindings=[
            ServerBinding(
                server_id="network-egress",
                tool_capabilities={
                    "http_request": ToolCapability(
                        allowed_domains=["api.github.com", "pypi.org"],
                        blocked_domains=["*.evil.example"],
                    )
                },
            ),
            ServerBinding(
                server_id="filesystem-local",
                tool_capabilities={
                    "read_file": ToolCapability(
                        allowed_paths=["/home/user/project/*"],
                        blocked_paths=["/home/user/.ssh/*"],
                    )
                },
            ),
        ],
    )


def test_extract_domain_from_url():
    paths, domains = extract_destination_candidates("http_request", {"url": "https://api.github.com/repos/foo"})
    assert domains == ["api.github.com"]
    assert paths == []


def test_extract_path_from_filesystem_args():
    paths, domains = extract_destination_candidates("read_file", {"path": "/home/user/project/main.py"})
    assert paths == ["/home/user/project/main.py"]


def test_allowed_domain_passes():
    policy = _policy()
    assert is_destination_allowed(policy, "network-egress", "http_request", {"url": "https://api.github.com/x"})


def test_non_allowlisted_domain_fails():
    policy = _policy()
    assert not is_destination_allowed(
        policy, "network-egress", "http_request", {"url": "https://attacker.example/x"}
    )


def test_blocked_domain_fails_even_if_pattern_looks_close():
    policy = _policy()
    assert not is_destination_allowed(
        policy, "network-egress", "http_request", {"url": "https://webhook.evil.example/x"}
    )


def test_unknown_server_id_fails_closed():
    policy = _policy()
    assert not is_destination_allowed(policy, "some-other-server", "http_request", {"url": "https://api.github.com"})


def test_unknown_tool_fails_closed():
    policy = _policy()
    assert not is_destination_allowed(policy, "network-egress", "totally_unknown_tool", {})


def test_no_referenced_destination_is_vacuously_allowed():
    policy = _policy()
    assert is_destination_allowed(policy, "network-egress", "http_request", {})


def test_read_from_blocked_path_is_sensitive_source():
    policy = _policy()
    assert is_sensitive_source(
        policy, "filesystem-local", "read_file", {"path": "/home/user/.ssh/id_rsa"}
    )


def test_read_from_normal_path_is_not_sensitive_source():
    policy = _policy()
    assert not is_sensitive_source(
        policy, "filesystem-local", "read_file", {"path": "/home/user/project/main.py"}
    )


def test_no_blocked_paths_configured_means_never_sensitive():
    policy = PolicyFile(
        version="test",
        server_bindings=[
            ServerBinding(
                server_id="filesystem-local",
                tool_capabilities={"read_file": ToolCapability(allowed_paths=["/tmp/*"])},
            )
        ],
    )
    assert not is_sensitive_source(policy, "filesystem-local", "read_file", {"path": "/tmp/anything"})
