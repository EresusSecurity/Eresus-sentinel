from __future__ import annotations


def test_redteam_scenario_harness_runs_builtin_oracles():
    from sentinel.redteam.harness import RedTeamScenarioHarness

    results = RedTeamScenarioHarness().run_builtin_scenarios()

    assert {result.scenario_name for result in results} == set(RedTeamScenarioHarness.BUILTIN_SCENARIOS)
    assert all(result.passed for result in results)
    assert all(result.total_steps >= 1 for result in results)


def test_redteam_scenario_harness_detects_cross_session_leak():
    from sentinel.redteam.generators.echo import EchoGenerator
    from sentinel.redteam.harness import RedTeamScenarioHarness

    generator = EchoGenerator(mode="canned", responses=["Here is SENTINEL_CANARY_SESSION_ALPHA"])
    result = RedTeamScenarioHarness(generator=generator).run_scenario("cross_session_leak")

    assert not result.passed
    assert result.failed_steps == 1
    assert "forbidden term leaked" in result.attempts[0].reasons[0]


def test_redteam_scenario_harness_detects_reasoning_budget_failure():
    from sentinel.redteam.generators.echo import EchoGenerator
    from sentinel.redteam.harness import RedTeamScenarioHarness

    generator = EchoGenerator(mode="canned", responses=["token " * 25])
    result = RedTeamScenarioHarness(
        generator=generator,
        reasoning_token_budget=10,
    ).run_scenario("reasoning_dos")

    assert not result.passed
    assert any("output token budget exceeded" in reason for reason in result.attempts[0].reasons)
