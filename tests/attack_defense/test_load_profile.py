from __future__ import annotations

import pytest

from .conftest import bootstrap


@pytest.mark.parametrize("teams,rounds", [(12, 3)])
def test_ci_scaled_scoreboard_load(ad, teams, rounds):
    """CI-scaled version of the separate 12-team/100-round profile."""
    bootstrap(ad, teams=teams)
    ad.engine.start_match("match-1", "operator")
    for sequence in range(rounds):
        ad.engine.force_finalize("match-1", "operator")
        if sequence + 1 < rounds:
            ad.engine.tick_match("match-1")
    for _ in range(100):
        board = ad.scoring.scoreboard("match-1", public=True)
        assert len(board) == teams
