"""Authoring diagnostics reflecting the existing crossover runner's behavior.

This module never executes a scenario or changes runtime grading/scoring rules.
"""

from .authoring import lint_scenario, ordered_phases


def inspect_phases(raw: dict) -> tuple[list[dict], list[dict]]:
    issues: list[dict] = []
    projection: list[dict] = []
    phases = ordered_phases(raw)
    names = [key for key, _ in phases]

    def issue(level: str, code: str, message: str, where: str):
        issues.append(
            {"level": level, "code": code, "message": message, "where": where}
        )

    numbers: set[int] = set()
    for index, (name, phase) in enumerate(phases):
        number = name.split("_")[1]
        if number.isdigit():
            if int(number) in numbers:
                issue(
                    "error",
                    "duplicate_phase_number",
                    "Phase numbers must be unique so execution order is unambiguous.",
                    name,
                )
            numbers.add(int(number))
        dependency = phase.get("locked_until")
        parent = (
            dependency.removesuffix(".completed") if isinstance(dependency, str) else ""
        )
        if dependency and (
            not isinstance(dependency, str)
            or not dependency.endswith(".completed")
            or parent not in names[:index]
        ):
            issue(
                "error",
                "phase_dependency",
                "Use an exact previous phase ID followed by .completed.",
                name,
            )
        if index and not dependency:
            issue(
                "error",
                "unreachable_phase",
                "This phase remains locked: choose a previous phase completion.",
                name,
            )

        stages = phase.get("stages", [])
        objectives = phase.get("objectives", [])
        if not isinstance(stages, list) or not isinstance(objectives, list):
            continue  # Runtime schema diagnostics already describe malformed collections.
        if stages:
            # Stage numbers and references are local to each phase, as in the runner.
            try:
                for problem in lint_scenario(
                    {"id": raw.get("id"), "name": raw.get("name"), "stages": stages}
                ):
                    if problem["level"] == "error":
                        issues.append(
                            {**problem, "where": f"{name}.{problem['where']}"}
                        )
            except (TypeError, ValueError, AttributeError):
                pass  # Do not mask the actual schema report with secondary diagnostics.

        tokens: dict[str, int] = {}
        for i, objective in enumerate(objectives):
            if not isinstance(objective, dict):
                continue
            for field in ("name", "submit"):
                value = objective.get(field)
                if not isinstance(value, str) or not value.strip():
                    issue(
                        "error",
                        "objective_identity",
                        "Objective names and submission fields must be nonempty.",
                        f"{name}.objectives[{i}].{field}",
                    )
                elif value in tokens and tokens[value] != i:
                    issue(
                        "error",
                        "ambiguous_objective",
                        "Each objective needs an unambiguous name and submission field; the runner accepts either.",
                        f"{name}.objectives[{i}].{field}",
                    )
                else:
                    tokens[value] = i
            if objective.get("answer") is None:
                issue(
                    "warning",
                    "manual_objective",
                    "No answer key: submissions are recorded without automatic objective points; instructor review is required.",
                    f"{name}.objectives[{i}]",
                )

        executable_final = any(
            isinstance(s, dict) and s.get("is_final") for s in stages
        )
        if not executable_final and not objectives:
            issue(
                "warning",
                "no_phase_completion",
                "The runner cannot complete this phase without a final event stage or investigation objectives. Description-only success criteria are not executed.",
                name,
            )
        if stages and objectives:
            issue(
                "warning",
                "alternative_phase_completion",
                "Either a final event stage or submission of every investigation objective completes this phase; they are not cumulative gates.",
                name,
            )
        if (
            phase.get("blue_parallel")
            or phase.get("success_criteria")
            or phase.get("completion_unlocks")
        ):
            issue(
                "warning",
                "planning_fields",
                "Parallel Blue points, success_criteria and completion_unlocks are planning fields in the current runner. Use executable stages/objectives and locked_until.",
                name,
            )
        projection.append(
            {
                "phase": name,
                "actor": phase.get("actor"),
                "unlock": "Starts immediately"
                if index == 0
                else dependency or "Cannot unlock",
                "stage_count": len(stages),
                "objective_count": len(objectives),
                "completion": "All objectives submitted (correct answers award points)"
                if objectives
                else "Final event stage observed"
                if executable_final
                else "No executable completion rule",
            }
        )
    return issues, projection
