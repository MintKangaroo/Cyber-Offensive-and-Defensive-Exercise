"""Unit tests for the pure helpers of the beginner Blue Team defense workflow."""
from __future__ import annotations

from scripts import beginner_defense as bd


def test_patch_reference_is_team_namespaced():
    ref = bd.patch_reference("registry.local:5000", "team-01", "vulnerable-notes", "beginner-1")
    assert ref == "registry.local:5000/team-01/vulnerable-notes:beginner-1"


def test_is_terminal_covers_engine_end_states():
    for status in ("deployed", "rejected", "failed"):
        assert bd.is_terminal(status)
    for status in ("uploaded", "validating", "approved", "deploying"):
        assert not bd.is_terminal(status)


def test_build_command_selects_the_patch_flag_and_lineage():
    cmd = bd.build_command(bd.NOTES, "localhost:5000/team-01/vulnerable-notes:t", "sha256:abc")
    assert cmd[0:2] == ["docker", "build"]
    assert "-f" in cmd and bd.NOTES.dockerfile in cmd
    assert "PATCH_IDOR=true" in cmd
    assert "CYBER_RANGE_BASE_DIGEST=sha256:abc" in cmd
    assert cmd[-1] == "."


def test_vault_spec_uses_traversal_flag():
    cmd = bd.build_command(bd.VAULT, "localhost:5000/team-01/file-vault:t", "sha256:def")
    assert "PATCH_TRAVERSAL=true" in cmd
    assert bd.VAULT.dockerfile in cmd


def test_specs_registered_for_both_services():
    assert set(bd.SPECS) == {"notes", "vault"}
    assert bd.SPECS["notes"].service_id == "service-vulnerable-notes"
    assert bd.SPECS["vault"].service_id == "service-file-vault"


def test_team_logins_align_with_public_ports():
    # Every login team must also have a published port for both services.
    for team_id in bd.TEAM_LOGINS:
        assert team_id in bd.NOTES.public_port_by_team
        assert team_id in bd.VAULT.public_port_by_team


def test_parse_args_defaults_to_notes_team01():
    args = bd.parse_args([])
    assert args.service == "notes"
    assert args.team == "team-01"
    assert args.dry_run is False
