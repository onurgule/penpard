# BrowserService Decomposition And Orchestrator Finish Pass

## 1. Objective

This pass focused on two linked goals:

- decomposing `BrowserService` into truer runtime/state/persistence/tool boundaries
- cleaning the remaining orchestrator integration impurities without destabilizing the single-agent production scan path

## 2. Governing context

The inherited architecture was already materially improved before this pass:

- `OrchestratorSingleAgentHarness` was already the real execution harness
- `OrchestratorScanState` was already the real mutable state container
- the control plane and domain-engine layer were already the strongest part of the backend and had to stay protected
- `OrchestratorAgent` was no longer the main god object, but still had some browser-related integration clutter and inline prompt/tool wiring residue

That left `BrowserService` as the most structurally dangerous blur. It still mixed:

- browser action execution
- Chromium lifecycle and visibility transitions
- in-memory live session ownership
- network event and JS artifact collection
- URL/domain classification
- direct DB persistence

That combination made the browser path harder to reason about, harder to test in seams, and riskier for future richer agent/browser coordination.

## 3. Pre-pass diagnosis

### BrowserService

Before this pass, `backend/src/services/BrowserService.ts` simultaneously owned:

- session map ownership and lifecycle truth
- browser launch/close/show/hide/reopen logic
- continuity snapshotting during visibility transitions
- crash/disconnect/manual-close handling
- request/response listener attachment
- browser-to-Burp traffic capture
- JS artifact capture and disk persistence
- DB session/action writes
- PenPard-internal URL filtering and restore URL decisions
- tool-facing browser actions and page inspection

That was the last place where tool logic, runtime logic, state, persistence, and a bit of domain policy still lied about belonging together.

### OrchestratorAgent

The remaining impurities were smaller but real:

- inline system prompt assembly still lived in `phaseInit()`
- continuation prompt assembly still needed the same truth
- browser-facing collaborators were still implicitly anchored to the global browser service
- tool inputs were still somewhat loose even after the dispatcher/registry split

`executeToolCall()` itself was already effectively thin because the real execution flow had already moved into the dispatcher; forcing another layer there would have been fake modularity.

## 4. What you changed

### Added

- `backend/src/services/browser/browserTypes.ts`
  - centralized browser runtime/session/tool types
- `backend/src/services/browser/BrowserSessionStore.ts`
  - owns in-memory live session registry, readiness checks, lifecycle transitions, and visibility state
- `backend/src/services/browser/BrowserSessionPersistence.ts`
  - owns DB writes/reads for browser sessions and browser actions, plus proxy config lookup
- `backend/src/services/browser/BrowserTelemetry.ts`
  - owns listener attachment, traffic capture, JS artifact capture, and session invalidation on page/context/browser events
- `backend/src/services/browser/BrowserUrlPolicy.ts`
  - owns target/internal/external URL classification and safe restore URL selection
- `backend/src/services/browser/BrowserRuntime.ts`
  - owns Chromium launch/close/relaunch, show/hide continuity transitions, crash/disconnect recovery, and desktop asset lookup
- `backend/src/services/browser/BrowserActionRunner.ts`
  - owns tool-facing browser actions, page/state inspection, screenshots, storage/cookie sync, frontend analysis, and browser/Burp correlation
- `backend/src/agents/orchestrator/OrchestratorBrowserRuntime.ts`
  - browser runtime contract for orchestrator browser collaborators
- `backend/src/agents/orchestrator/OrchestratorSystemPromptBuilder.ts`
  - extracted system prompt assembly from `OrchestratorAgent`
- `backend/test/browser-url-policy.test.ts`
  - seam coverage for extracted URL classification/restore logic
- `backend/test/orchestrator-browser-session.test.ts`
  - seam coverage for injected browser runtime relaunch behavior

### Modified

- `backend/src/services/BrowserService.ts`
  - reduced from an all-in-one implementation to a composition-root façade over the extracted browser seams
- `backend/src/agents/OrchestratorAgent.ts`
  - uses `OrchestratorSystemPromptBuilder` for both continuation and init prompt construction
  - injects the browser runtime into browser collaborators through a contract
  - tightened tool-handler call sites for the typed tool surface
- `backend/src/agents/orchestrator/OrchestratorBrowserSession.ts`
  - now depends on `OrchestratorBrowserRuntime` instead of only the concrete global service
- `backend/src/agents/orchestrator/OrchestratorBrowserTools.ts`
  - same runtime contract cleanup as above
- `backend/src/agents/orchestrator/types.ts`
  - introduced `ToolArgsByName`, `KnownToolName`, and generic `ToolCall<TTool>`
- `backend/src/agents/orchestrator/OrchestratorToolRegistry.ts`
  - normalized known tool names back into the typed tool surface
- `backend/src/agents/orchestrator/OrchestratorRequestExecutor.ts`
  - consumes the stricter `ToolCall<'send_http_request'>`
- `backend/src/agents/orchestrator/OrchestratorDomainCoordinator.ts`
  - consumes stricter typed tool calls for domain-engine tools

### Removed

- no production capability was removed
- the old giant `BrowserService` implementation body was replaced by the façade plus extracted collaborators

## 5. Boundary decisions

| Area | Decision | Why |
| --- | --- | --- |
| Browser action execution | Extracted | `BrowserActionRunner` now owns tool-facing browser actions and browser-state inspection, so runtime lifecycle and persistence are no longer fused with the action surface. |
| Browser session lifecycle | Extracted | `BrowserRuntime` now owns Chromium launch/close/relaunch/show/hide continuity transitions and recovery behavior. |
| Browser state ownership | Extracted | `BrowserSessionStore` now owns the live session registry, readiness checks, and lifecycle truth. |
| Browser persistence | Extracted | `BrowserSessionPersistence` now owns DB writes/reads instead of runtime/tool code writing straight into DB helpers. |
| Browser/domain classification logic | Extracted | `BrowserUrlPolicy` now owns internal-vs-target-vs-external URL classification and restore URL safety rules. |
| Browser telemetry capture | Extracted | `BrowserTelemetry` now owns listener attachment, traffic capture, JS artifact capture, and invalidation on crash/disconnect/manual close. |
| Orchestrator integration glue | Extracted and hardened | system prompt construction moved to `OrchestratorSystemPromptBuilder`; browser collaborators now depend on `OrchestratorBrowserRuntime`; `executeToolCall()` was hardened in place because dispatcher ownership was already the truthful seam. |
| Findings/evidence/auth/browser quality protection | Hardened in place | the pass preserved the active scan path and did not push auth or finding logic down into runtime helpers. |
| Domain-engine layer | Hardened in place | `RequestHarvester`, `HypothesisEngine`, `CoverageTracker`, `OrchestratorDomainCoordinator`, and related engines were intentionally not restructured. |
| Future multi-agent extensibility | Extracted where useful, rejected where fake | central browser seams and the orchestrator browser runtime contract improve future agent composition; no dormant multi-agent behavior was reactivated. |
| Further splitting `BrowserActionRunner` | Rejected for this pass | more fragmentation here would have been speculative; the current extraction already moved the dangerous ownership blur out of runtime/state/persistence. |
| Re-extracting `executeToolCall()` into yet another wrapper | Rejected | dispatcher ownership already told the truth; another façade would have been wrapper spam. |

## 6. Before vs after ownership map

### Before

`BrowserService` owned:

- browser process lifecycle
- browser visibility transitions
- live session map
- listener attachment
- traffic history
- JS artifact capture and persistence
- URL classification and internal filtering
- DB session/action persistence
- all tool-facing browser operations

`OrchestratorAgent` still directly coordinated:

- inline system prompt construction
- concrete browser service usage through browser collaborators rather than a runtime contract
- a looser tool argument surface

### After

`BrowserService` now owns only:

- composition of the extracted browser collaborators
- the stable public façade expected by the rest of the app and existing routes/tests

Ownership now sits in the following real seams:

- `BrowserSessionStore`: live session registry and lifecycle truth
- `BrowserSessionPersistence`: DB persistence
- `BrowserTelemetry`: network events, JS artifacts, and browser event invalidation
- `BrowserUrlPolicy`: internal/target/external URL policy and restore policy
- `BrowserRuntime`: lifecycle and visibility transitions
- `BrowserActionRunner`: tool-facing browser actions and inspection

`OrchestratorAgent` no longer directly coordinates:

- inline prompt-template assembly for init/continuation
- concrete browser runtime coupling inside browser session/tools

## 7. Test stability and regression impact

### Browser seam extraction

Existing tests that remained unchanged:

- `backend/test/browser-visibility.test.ts`
- `backend/test/endpoint-intelligence.test.ts`
- `backend/test/socketio-burp-noise.test.ts`

New tests added:

- `backend/test/browser-url-policy.test.ts`

Why:

- the URL classification/restore logic became its own seam and deserved direct coverage because it is part of the show/hide/reopen continuity path

Churn assessment:

- low churn
- no existing browser lifecycle tests needed rewrites
- extraction proved stable because the unchanged lifecycle tests still passed

### Orchestrator browser/runtime cleanup

Existing tests that remained unchanged:

- `backend/test/orchestrator-tooling.test.ts`
- `backend/test/orchestrator-lifecycle.test.ts`
- `backend/test/orchestrator-scan-surface.test.ts`
- `backend/test/orchestrator-request-executor.test.ts`
- `backend/test/orchestrator-domain-coordinator.test.ts`

New tests added:

- `backend/test/orchestrator-browser-session.test.ts`

Why:

- the browser runtime contract injection was a new seam and needed direct proof that relaunch/auth reseed behavior still works through the injected dependency rather than only the global browser singleton

Churn assessment:

- low churn
- no existing orchestrator focused tests needed updates
- extraction proved stable because unchanged orchestrator/runtime tests still passed

### Build/type stability

During implementation, two non-final regressions surfaced and were corrected:

1. `BrowserActionRunner.ts` initially failed the build because a template literal was embedded inside the browser-evaluated string. That was corrected by switching the inner push to string concatenation.
2. the tightened tool typing exposed registry and handler wiring mismatches in `OrchestratorToolRegistry.ts` and `OrchestratorAgent.ts`. Those were corrected by normalizing canonical tool names back into `KnownToolName` and by routing specific handlers through typed `ToolCall<'...'>` casts at the registration seam.

Final verification passed after those corrections.

## 8. Verification

### Commands run

1. `cmd /c npm run build`
   - final status: passed

2. `cmd /c node --import tsx --test test/browser-visibility.test.ts test/browser-url-policy.test.ts test/orchestrator-browser-session.test.ts test/orchestrator-tooling.test.ts test/orchestrator-lifecycle.test.ts test/orchestrator-scan-surface.test.ts test/orchestrator-request-executor.test.ts test/orchestrator-domain-coordinator.test.ts test/scan-runtime-service.test.ts test/endpoint-intelligence.test.ts test/auth-state.test.ts test/web-auth-startup-config.test.ts test/burp-auth-regression.test.ts test/socketio-burp-noise.test.ts`
   - final status: passed
   - result: 61 tests passed, 0 failed

### Verification outcome

- backend build passed
- focused browser/orchestrator/runtime/auth/Burp tests passed
- new seam tests passed
- no broken imports or type regressions remained in the final build

## 9. Regressions checked

The verification set explicitly checked:

- auth-first startup and auth route selection
- auth sync from browser cookies/storage
- browser session continuity
- show/hide visibility transitions
- manual-close handling
- crash/disconnect recovery and controlled reopen
- browser-assisted workflows and frontend analysis aftermath
- browser/Burp correlation and noise filtering
- Burp request execution and auth-aware replay behavior
- endpoint discovery and endpoint inventory refresh
- runtime finalization truth
- stop/pause/final terminal phase truth
- checkpoint persistence fallback

## 10. Residual risk

The pass materially reduced the real blur, but two imperfections remain:

1. `BrowserActionRunner` is still a fairly dense tool-facing module. That is intentional for now. Splitting it further in this pass would have risked fake modularity after the real runtime/state/persistence seams had already been carved out.
2. `OrchestratorAgent.ts` still contains an inert legacy prompt branch under `if (false && this.config.customSystemPrompt)` near the phase-init prompt path. The live behavior now comes from `OrchestratorSystemPromptBuilder`, and the branch does not affect runtime behavior, but the file still has a small amount of dead prompt-era residue that should be deleted in a future low-risk cleanup once the historical literal is normalized cleanly.

## 11. Final verdict

Yes.

This pass materially reduced the remaining critical structural blur in `BrowserService` and improved orchestrator cleanliness without degrading the working production scan path.

The result is not a fake file split. Runtime lifecycle, live state, persistence, telemetry, URL policy, and tool-facing browser execution now have clearer ownership, while the active single-agent production path, auth-first startup, browser continuity, Burp correlation, endpoint intelligence, and runtime truth all stayed intact under focused verification.
