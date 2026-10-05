from __future__ import annotations

from unittest.mock import patch
import pytest

from unpack.utils.wait import SmartWaiter, WaitResult


class TestWaitResult:
    def test_fields(self):
        r = WaitResult(waited_seconds=5.0, reason="threads_stable", thread_counts=[10, 12, 12, 12])
        assert r.waited_seconds == 5.0
        assert r.reason == "threads_stable"


class TestSmartWaiter:
    def test_stabilization_detection(self):
        counts = iter([5, 8, 12, 15, 15, 15])
        waiter = SmartWaiter(poll_interval=0.01, stable_rounds=3, max_wait=60, min_wait=0)
        with patch.object(waiter, '_get_thread_count', side_effect=counts):
            with patch.object(waiter, '_check_logcat_ready', return_value=False):
                with patch('unpack.utils.wait.time') as mock_time:
                    # Simulate elapsed time: each call to monotonic advances
                    call_count = [0]
                    def fake_monotonic():
                        val = call_count[0] * 0.5
                        call_count[0] += 1
                        return val
                    mock_time.monotonic = fake_monotonic
                    mock_time.sleep = lambda x: None
                    result = waiter.wait(serial="fake", pid="1234")
        assert result.reason == "threads_stable"
        assert result.thread_counts[-3:] == [15, 15, 15]

    def test_max_wait_timeout(self):
        waiter = SmartWaiter(poll_interval=0.01, stable_rounds=3, max_wait=2.0, min_wait=0)
        call_count = [0]
        with patch.object(waiter, '_get_thread_count', return_value=call_count):
            def changing_count(serial, pid):
                call_count[0] += 1
                return call_count[0]  # never stabilizes
            waiter._get_thread_count = changing_count
            with patch.object(waiter, '_check_logcat_ready', return_value=False):
                with patch('unpack.utils.wait.time') as mock_time:
                    elapsed = [0.0]
                    def fake_monotonic():
                        elapsed[0] += 0.5
                        return elapsed[0]
                    mock_time.monotonic = fake_monotonic
                    mock_time.sleep = lambda x: None
                    result = waiter.wait(serial="fake", pid="1234")
        assert result.reason == "max_wait"

    def test_logcat_keyword_triggers(self):
        waiter = SmartWaiter(poll_interval=0.01, stable_rounds=5, max_wait=60, min_wait=0)
        logcat_calls = [False, False, True]
        logcat_iter = iter(logcat_calls)
        with patch.object(waiter, '_get_thread_count', return_value=10):
            with patch.object(waiter, '_check_logcat_ready', side_effect=logcat_iter):
                with patch('unpack.utils.wait.time') as mock_time:
                    call_count = [0]
                    def fake_monotonic():
                        val = call_count[0] * 1.0
                        call_count[0] += 1
                        return val
                    mock_time.monotonic = fake_monotonic
                    mock_time.sleep = lambda x: None
                    result = waiter.wait(serial="fake", pid="1234")
        assert result.reason == "logcat_ready"

    def test_process_died_detected(self):
        waiter = SmartWaiter(poll_interval=0.01, stable_rounds=3, max_wait=60, min_wait=0)
        with patch.object(waiter, '_get_thread_count', return_value=None):
            with patch('unpack.utils.wait.time') as mock_time:
                mock_time.monotonic = lambda: 0.0
                mock_time.sleep = lambda x: None
                result = waiter.wait(serial="fake", pid="1234")
        assert result.reason == "process_died"

    def test_min_wait_respected(self):
        """Even if threads stabilize immediately, respect min_wait."""
        counts = iter([10, 10, 10, 10, 10, 10])
        waiter = SmartWaiter(poll_interval=0.01, stable_rounds=3, max_wait=60, min_wait=5.0)
        with patch.object(waiter, '_get_thread_count', side_effect=counts):
            with patch.object(waiter, '_check_logcat_ready', return_value=False):
                with patch('unpack.utils.wait.time') as mock_time:
                    call_count = [0]
                    def fake_monotonic():
                        val = call_count[0] * 2.0  # 0, 2, 4, 6 -> stable at round 3 but elapsed=6 > min_wait=5
                        call_count[0] += 1
                        return val
                    mock_time.monotonic = fake_monotonic
                    mock_time.sleep = lambda x: None
                    result = waiter.wait(serial="fake", pid="1234")
        assert result.reason == "threads_stable"
        assert result.waited_seconds >= 5.0
