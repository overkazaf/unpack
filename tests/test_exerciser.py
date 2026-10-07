from __future__ import annotations

from unittest.mock import patch
import pytest

from unpack.utils.exerciser import AppExerciser, ExerciseResult


class TestExerciseResult:
    def test_fields(self):
        r = ExerciseResult(actions_performed=5, duration_seconds=3.2)
        assert r.actions_performed == 5
        assert r.duration_seconds == 3.2


class TestAppExerciser:
    def test_exercise_runs_interactions(self):
        exerciser = AppExerciser(rounds=1, delay=0.0)
        with patch.object(exerciser, '_run_action') as mock_action:
            result = exerciser.exercise("fake-serial", "com.test.app")
        assert mock_action.call_count > 0
        assert result.actions_performed > 0

    def test_exercise_respects_rounds(self):
        exerciser = AppExerciser(rounds=3, delay=0.0)
        actions = []
        def track_action(serial, pkg, action):
            actions.append(action)
        with patch.object(exerciser, '_run_action', side_effect=track_action):
            exerciser.exercise("fake-serial", "com.test.app")
        # 3 rounds * 7 actions per round = 21
        assert len(actions) == 21

    def test_exercise_single_round(self):
        exerciser = AppExerciser(rounds=1, delay=0.0)
        with patch.object(exerciser, '_run_action') as mock:
            result = exerciser.exercise("s", "p")
        # 1 round * 7 actions = 7
        assert result.actions_performed == 7
