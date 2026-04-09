# PenPard Runtime Boundary Refactor — Implementation Walkthrough

## Objective
This refactor targeted the highest-risk runtime boundary violations from the hard-boundary report:

- route-owned scan runtime lifecycle state
- hidden active agent and pool registries living in `routes/scans.ts`
- runtime log/cache ownership spread across route files
- `OrchestratorAgent.ts` directly owning scan-status side effects, tool dispatch routing, and guard/helper logic

The goal was to materially reduce control-plane leakage and orchestrator role collapse without rewriting the scan engine or contaminating the clean domain-engine layer.

## Input Findings Used
The implementation was driven directly by these report findings:

- `OrchestratorAgent.ts` was the critical quad-hybrid god object.
- control-plane behavior was split between `routes/scans.ts` and `OrchestratorAgent.ts`.
- active runtime registries were embedded as module-level `Map`s in `routes/scans.ts`.
- runtime state ownership was fragmented across memory caches and persistence access paths.
- the highest-value fixes were at the runtime/control boundary, not inside the domain engines.
- clean domain-engine components had to remain protected.

## Changes by Phase

### Phase 1 — Extract and isolate control-plane ownership
I created a dedicated runtime layer under `backend/src/services/runtime/`:

- `ScanRuntimeRegistry` now owns active orchestrator handles, active pool handles, and cached scan log snapshots.
- `ScanRuntimeService` now owns runtime handle resolution, pause/resume/stop/continue routing, live-status shaping, browser handle resolution, assisted-scan startup, and normal web scan startup/finalization.
- `routes/scans.ts` no longer owns the active runtime maps or the log cache directly.
- `routes/activity-monitor.ts` no longer reaches into `routes/scans.ts` to mutate scan runtime globals.

This turns runtime lifecycle ownership into an explicit service boundary instead of a route-module side effect.

### Phase 2 — Reduce `OrchestratorAgent` role collapse
I extracted the highest-value seams from `OrchestratorAgent.ts` into dedicated collaborators under `backend/src/agents/orchestrator/`:

- `OrchestratorToolDispatcher` owns the tool handler registry and dispatch path.
- `OrchestratorToolPolicy` owns focused-scope blocking, rate-limit gating, and extracted auth/tool helper functions.
- `OrchestratorScanStatus` owns scan-status writes so the orchestrator no longer calls `updateScanStatus()` directly.
- `types.ts` now provides the shared tool-call contract for orchestrator collaborators.

`OrchestratorAgent` still coordinates runtime execution, but it no longer directly owns the tool switchboard or raw status writes.

### Phase 3 — Make runtime state boundaries more explicit
I centralized volatile runtime state access patterns:

- active runtime lookup now goes through `ScanRuntimeRegistry`
- live polling now resolves runtime handles through `ScanRuntimeService`
- cached runtime logs now live in one registry instead of hidden route globals
- endpoint inventory lookup prefers active runtime state through the runtime service, then falls back to persistence
- continuation scans and activity-monitor-assisted scans now register/unregister through the same runtime service

This makes it much clearer which state is volatile in-memory runtime state and which state is persisted in the database.

### Phase 4 — Protect the clean layers
I deliberately did not move or rework the clean domain layers:

- `HypothesisEngine`
- `CoverageTracker`
- `ResponseDiffer`
- `RequestHarvester`
- auth subsystem internals
- `BurpMCPClient`
- `LLMProviderService`
- `LLMQueue`

The refactor stayed focused on runtime/control ownership and orchestrator seams.

### Phase 5 — Verification and documentation
I added focused tests for the new runtime and orchestrator seams and re-ran the backend build and full backend test suite after the refactor.

## Files Added

- `backend/src/services/runtime/ScanRuntimeRegistry.ts`
  Central runtime registry for active agents, active pools, and cached scan log snapshots.

- `backend/src/services/runtime/ScanRuntimeService.ts`
  Runtime control-plane service for startup, continuation, stop/pause/resume, live-status resolution, browser visibility routing, and assisted scans.

- `backend/src/agents/orchestrator/types.ts`
  Shared tool-call type for extracted orchestrator collaborators.

- `backend/src/agents/orchestrator/OrchestratorScanStatus.ts`
  Encapsulates scan-status updates for the orchestrator.

- `backend/src/agents/orchestrator/OrchestratorToolPolicy.ts`
  Encapsulates focused-scope guards, rate-limit guards, and auth/tool helper logic.

- `backend/src/agents/orchestrator/OrchestratorToolDispatcher.ts`
  Explicit tool dispatch registry and execution router for orchestrator tool calls.

- `backend/test/scan-runtime-registry.test.ts`
  Tests the explicit runtime registry ownership model.

- `backend/test/orchestrator-tooling.test.ts`
  Tests the extracted orchestrator dispatch and policy seams.

- `implementation-walkthrough.md`
  This implementation report.

## Files Modified

- `backend/src/routes/scans.ts`
  Removed route-level runtime ownership. Route handlers now delegate runtime lifecycle control, live status, browser resolution, continuation startup, and endpoint-inventory runtime lookup to `ScanRuntimeService`.

- `backend/src/routes/activity-monitor.ts`
  Removed cross-route mutation of `scans.ts` globals. Assisted scans now go through `ScanRuntimeService`.

- `backend/src/agents/OrchestratorAgent.ts`
  Replaced direct status writes with `OrchestratorScanStatus`, replaced embedded tool routing with `OrchestratorToolDispatcher`, and switched auth/tool helper usage to extracted policy helpers.

## Boundary Improvements Achieved

- **Control Plane vs Route Transport**
  `routes/scans.ts` is now much thinner on runtime ownership. It validates HTTP input and delegates lifecycle operations to `ScanRuntimeService`.

- **Control Plane vs Runtime State**
  Active scan runtime handles now live in `ScanRuntimeRegistry`, not in module-level route globals.

- **Runtime State vs Persistence**
  Cached live logs and active runtime handles are now clearly volatile runtime state, while DB lookups remain persistence fallback paths.

- **Harness/Runtime Coordination vs Agent Internals**
  The orchestrator no longer directly owns raw scan-status DB writes or the tool dispatch registry.

- **Agent vs Tool Dispatch/Guard Logic**
  Tool execution policy and routing are now explicit collaborators instead of being embedded inline in the orchestrator monolith.

- **Cross-Route Runtime Ownership**
  `activity-monitor.ts` no longer imports runtime globals from `scans.ts`, which removes a hidden control-plane coupling point.

## What Was Intentionally Not Changed

- I did not rewrite the scan algorithm or the plan/execute/replan loop.
- I did not change the domain-engine methodology in `HypothesisEngine`, `CoverageTracker`, `ResponseDiffer`, or `RequestHarvester`.
- I did not split the auth subsystem internals apart.
- I did not change `BurpMCPClient`, `BrowserService`, `LLMProviderService`, or `LLMQueue`.
- I did not attempt crash-resume persistence for active runtimes.
- I did not force a broader `AgentPool` redesign because the report identified the single-orchestrator runtime/control boundary as the higher-value fix.

## Verification

Commands run:

- `cmd /c npm run build` in `backend/`
  Passed.

- `cmd /c npm test` in `backend/`
  Passed. Full backend suite completed successfully with 50 passing tests.

- `cmd /c npm run build` in `backend/` after response-mapping cleanup
  Passed.

- `cmd /c npm test` in `backend/` after response-mapping cleanup
  Passed. Full backend suite completed successfully with 50 passing tests.

## Residual Structural Debt

- `OrchestratorAgent.ts` is materially cleaner, but it is still the main runtime coordinator and still contains substantial planning/execution behavior.
- `ScanRuntimeService` is intentionally load-bearing now; it is a much better boundary than route-owned globals, but it still combines several runtime control responsibilities that could later be split into startup/finalization/status sub-services if needed.
- `AgentPool` still exposes limited pause-state detail, so pool live status remains less expressive than single-agent live status.
- Runtime state is clearer, but active scans are still process-local and in-memory.
- Continuation/follow-up chat behavior still partly lives in the route because completed-scan LLM Q&A remains an HTTP-facing concern.

## Final Outcome
PenPard now has an explicit runtime control-plane layer instead of hidden route-module ownership. Active scan handles, log snapshots, browser/runtime resolution, and lifecycle commands are centralized behind runtime services. `OrchestratorAgent` still coordinates scans, but tool routing, tool guard logic, and scan-status side effects now have explicit seams. The domain moat stayed untouched, the backend still builds, and the full backend test suite passes after the refactor.
