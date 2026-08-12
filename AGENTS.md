<!-- codex-workflow-id: viettran-edgeAI/codex_workflow -->
<!-- codex-workflow-managed-start -->
# AGENTS.md

## Project Context


## Design Principles

The project must strictly follow modular design.

Each module should have:

- A clear responsibility.
- A clear interface.
- Minimal unnecessary coupling.
- A structure that makes it easy to test, debug, replace, extend, and reuse.

Nested modules are allowed when they make responsibilities clearer. Avoid placing unrelated responsibilities into the same file, class, service, or large function.

- Define proportionate acceptance and verification requirements before implementation.
- Keep related tests cohesive enough to avoid fragmented micro-tests, but never reduce meaningful coverage, weaken assertions, or hide failures merely to save tokens or execution time.

Project personalization and project-local instructions appear in protected
regions at the end of this file. They override conflicting workflow defaults
for this project but do not override higher-level instructions.

## Working State

At any given time, we will be in one of two working states:
- `deployment state`: beginning to plan a broad task or in the process of deploying a plan. A  deployment plan can span multiple sessions.
- `leaf state`: for tasks outside the plan being deployed by the `deployment state`, such as general queries, document editing, or performing operations to add, modify, or delete small files, modules, or tools.

## Project Documentation Framework

The main project documents are stored under `agent_docs/`:

- `agent_docs/project_overview.md`: goals, architecture, workflow, and major decisions.
- `agent_docs/project_core_tech.md`:A brief summary of special technologies or architectures of project.
- `agent_docs/project_structure.md`: directory layout, modules, components, and ownership boundaries.
- `agent_docs/project_progress.md`: concise overall deployment progress, current position, and next milestone.
- `agent_docs/project_diary.md`: durable architecture decisions, discarded approaches, and lessons.
- `agent_docs/latest_session_work.md`: detailed latest-session state, evidence, unfinished work, and continuation point.
- Module-specific documents, when present.

The shared workflow runtime is installed under `~/.codex/codex_workflow/`:

- `~/.codex/codex_workflow/explorer_companion.md`: role, scope, lifecycle, and
  usage rules for the deployment-session explorer.
- `~/.codex/codex_workflow/end_of_session.md`: shared Medium/Heavy trigger and
  delegation contract for the dedicated handoff worker.

--------
`agent_docs/project_progress.md` and `agent_docs/latest_session_work.md` ensure smooth deployment across multiple sessions. During runtime, they may be edited only in `deployment state` or when the user explicitly requests it. The main agent owns both files during normal execution. The dedicated `end_of_session` worker owns them during an invoked handoff; no other subagent may edit them.

Update documentation only with verified facts. Keep temporary reasoning, raw logs, and short-lived checkpoints out of durable project documents.

Never delete any main project document without warning the user and receiving a second explicit confirmation.


## Route Selection

There are three routes.
### Light route: 
Use for light tasks which in the `leaf state`.
Performs tasks by yourself. Do not spawn subagents in this route.

### Medium route: 
Use for deploying large tasks/plans in the `deployment state`.
Perform implementation, verification, and documentation by yourself. Do not spawn implementation workers in this route. Explorer and the dedicated End-of-Session worker are the only subagent exceptions.
Read and follow `~/.codex/codex_workflow/medium_route.md`.

### Heavy route: 
You a orchestrator, coordinates subagents to deploy large tasks/plans in the `deployment state`.
Read and follow `~/.codex/codex_workflow/heavy_route.md`.

### Route selection rules and state interpolation

The route will be specified by the user, like: "use Light/medium/heavy route...". Apply that route throughout the entire session until it ends or until the user indicates to switch to the other route. If the user does not specify a route, select the light route as the default. Do not guess and choose a route yourself.

If the light route is specified or choosed, it means we are in the `leaf state`. 
If the medium route/heavy route is specified, it means we will proceed to the `deployment state`. 

## Context Loading

- In the Light route (`leaf state`), read only the files relevant to the current task.
- On first entering the `deployment state`, read and follow `~/.codex/codex_workflow/explorer_companion.md`, then initialize the explorer as directed there.
- Load the foundational project context in one bounded read-only batch:
  1. `agent_docs/project_overview.md`
  2. `agent_docs/project_structure.md`
  3. `agent_docs/project_progress.md`
  4. `agent_docs/latest_session_work.md`
- After the batch returns, interpret overview and structure before reconciling progress and the latest-session handoff. This interpretation order does not require separate outer tool calls.
- Use the resulting status and ownership map to inspect the smallest relevant interfaces, call sites, tests, and configuration surface.
- Read only relevant module documentation. Expand source inspection only when repository evidence requires it.
- Reconstruct active tasks, dependencies, verification state, and blockers. Resolve contradictions with targeted evidence.
- Under the Heavy route, review only critical hunks and integration boundaries after delegation unless risk, missing evidence, or conflicting results require broader inspection.

## Platform-specific paths

Paths in this workflow are written using `/` as a platform-neutral separator.
When running filesystem commands, use paths appropriate for the current operating system and shell:

* On Linux and macOS, use `/`.
* On Windows, use the equivalent Windows path format and `\` where required.

Do not treat the example path separator as a literal requirement. Resolve every path using the conventions of the current environment.
<!-- codex-workflow-managed-end -->

<!-- codex-workflow-project-personalization-start -->
<!-- codex-workflow-project-personalization-end -->

<!-- codex-workflow-project-local-instructions-start -->
## Automatic Route Selection

Select the route automatically for each substantive user request unless the user
explicitly names a route. An explicit route always wins. Continue an active
deployment plan on its current route unless the user changes it.

- Use Light for questions, reviews, documentation-only work, and small localized
  changes whose implementation and verification fit comfortably in the main
  agent's context.
- Use Medium for cohesive multi-file work that benefits from the deployment
  documentation framework but has little safe parallelism.
- Use Heavy when the task spans multiple modules, has two or more independent
  investigation or implementation workstreams, requires substantial debugging
  and verification, or is likely to create enough tool output to pollute the
  main agent's context.
- Start with the least expensive route that clearly fits. Escalate when repository
  evidence reveals greater scope; do not downgrade an active deployment merely
  because one remaining step is small.
- In Heavy, keep the main agent as the knowledge plane and task allocator. Send
  workers bounded task capsules containing goals, constraints, interfaces,
  invariants, ownership, and acceptance evidence. Workers report only material
  knowledge deltas, decisions, changed paths, verification results, and blockers;
  omit raw logs and routine tool traces.
- Delegate independent work concurrently within configured limits. Do not create
  workers for trivial work or duplicate the same investigation across workers.
<!-- codex-workflow-project-local-instructions-end -->
