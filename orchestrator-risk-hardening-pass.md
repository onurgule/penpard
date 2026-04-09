# Orchestrator Risk Hardening Pass

## 1. Objective
This pass targeted operational risk reduction and production hardening, not cosmetic refactoring.

The work focused on:
- reducing remaining `OrchestratorAgent` ownership risk without collapsing existing seams
- improving terminal/runtime truth around stop/finalization behavior
- fixing the visible agent-log mojibake defect in a durable, production-facing way
- removing one dead legacy Burp lifecycle path that still carried status/lifecycle ambiguity

## 2. Governing Context
The repository was already past the first extraction stage. Real seams already existed and were preserved:
- `OrchestratorPlanner`
- `OrchestratorInstructionAnalyzer`
- `OrchestratorLlmResponseParser`
- `OrchestratorBrowserSession`
- `OrchestratorRequestExecutor`
- `OrchestratorFindingTracker`
- `OrchestratorFallbackPlanner`
- `OrchestratorContextSignals`
- `OrchestratorToolDispatcher`
- `OrchestratorToolPolicy`
- `OrchestratorScanStatus`
- `ScanRuntimeService`
- `ScanRuntimeRegistry`

I treated the current state as functionally working but structurally risky in a few specific places:
- `OrchestratorAgent` still carried too much direct ownership for some operator-facing/runtime concerns
- runtime finalization order still allowed truth drift at stop time
- visible scan logs were still vulnerable to Unicode/mis-decoding corruption
- `BurpMCPClient` still contained an old lifecycle/status-driving path that no longer matched the current architecture

I did not refactor `cli.ts`, did not touch the clean pentest domain engines, and did not pollute the auth subsystem with cross-cutting abstractions.

## 3. Mojibake / Log Bug Analysis
### Observed symptom
Production-facing logs could show corrupted sequences such as:
- `âœ“` instead of `✓`
- `ğŸ“š` instead of `📚`
- `â•â•â•` instead of box separators
- `â†’` instead of `→`

### Trace result
I traced the log path through:
- log construction in `backend/src/agents/OrchestratorAgent.ts`
- log buffering/persistence
- SQLite `scan_logs` persistence in `backend/src/db/init.ts`
- file writes in the orchestrator log save path
- `/scans/:id/live` retrieval through `ScanRuntimeService`
- frontend rendering in `frontend/src/app/scan/[id]/MissionControlClient.tsx`

### Root cause
The exact mismatch was UTF-8 decorative log glyphs being surfaced through Windows-facing/operator-facing sinks as legacy-codepage-decoded text, producing sequences like `âœ“` and `â†’`.

Important negative findings:
- I did not find a DB schema problem. `scan_logs.message` is normal SQLite `TEXT`.
- I did not find a frontend renderer bug. The frontend was rendering the strings it received.
- I did not find a JSON/API serializer bug in the scan live path.

That means the failure was not best fixed in the UI or DB layer. The vulnerable boundary was the operator-visible scan-log ingress itself: raw Unicode/decorative log strings were being passed straight into persistence, file writes, and logger emission.

### Chosen fix
I added `backend/src/agents/orchestrator/OrchestratorLogLedger.ts` and made `OrchestratorAgent` write logs through it.

The ledger now:
- formats logs in one place
- incrementally flushes only new log entries to `scan_logs`
- writes UTF-8 snapshots to disk
- normalizes visible log output into a stable ASCII-safe readable subset before persistence/rendering

Examples of normalization:
- `✓` / `âœ“` -> `[ok]`
- `📚` / `ğŸ“š` -> `[mindset]`
- `🌐` / `ğŸŒ` -> `[browser]`
- `→` / `â†’` -> `->`
- box-drawing separators -> `===`

### Why this fix is correct
This is the narrowest durable fix because it hardens the single boundary that all scan logs already pass through.

It avoids:
- partial UI-only repair
- DB-only repair that still leaves live logs vulnerable
- deleting all formatting everywhere in the codebase

It preserves readability, keeps the system behavior intact, and removes downstream dependency on platform codepage behavior for visible scan logs.

### Regression protection added
Added coverage in `backend/test/orchestrator-log-ledger.test.ts` for:
- mojibake repair examples
- clean Unicode marker normalization
- UTF-8 file snapshot output
- incremental DB flush behavior

## 4. What I Changed
### Added
- `backend/src/agents/orchestrator/OrchestratorLogLedger.ts`
  Reason: real ownership seam for log normalization, buffering, incremental flush, and file persistence.
- `backend/src/agents/orchestrator/OrchestratorContextSignals.ts`
  Reason: real ownership seam for auth-startup reminders and action-budget pressure signaling.
- `backend/src/agents/orchestrator/OrchestratorFallbackPlanner.ts`
  Reason: real ownership seam for fallback planning when LLM planning does not return a usable plan.
- `backend/test/orchestrator-log-ledger.test.ts`
  Reason: regression coverage for the mojibake/log path.
- `backend/test/orchestrator-context-signals.test.ts`
  Reason: regression coverage for budget/auth signaling behavior.
- `backend/test/orchestrator-fallback-planner.test.ts`
  Reason: regression coverage for fallback-plan ownership and auth-first planning.

### Modified
- `backend/src/agents/OrchestratorAgent.ts`
  Reason: moved log persistence/normalization to `OrchestratorLogLedger`, delegated budget/auth reminder ownership to `OrchestratorContextSignals`, delegated fallback plan ownership to `OrchestratorFallbackPlanner`, ensured browser cleanup runs in terminal/failure paths, and made `stop()` clear paused state for truthful terminal runtime state.
- `backend/src/services/runtime/ScanRuntimeService.ts`
  Reason: fixed finalization ordering so stop happens before log capture/final flush, removed assisted-scan duplicate log persistence, and consolidated pool finalization.
- `backend/src/routes/scans.ts`
  Reason: added missing ownership checks before scan command/chat/live/browser-control side effects.
- `backend/src/services/burp-mcp.ts`
  Reason: removed dead legacy scan/status-driving path that no longer matched the current architecture.
- `backend/test/browser-visibility.test.ts`
  Reason: aligned browser continuity test to the browser-session seam rather than a stale wrapper.
- `backend/test/burp-auth-regression.test.ts`
  Reason: aligned tests to `OrchestratorRequestExecutor` and `OrchestratorFallbackPlanner` seams instead of reaching through stale agent helpers.
- `backend/test/orchestrator-lifecycle.test.ts`
  Reason: added stop/failure/cleanup truth tests.
- `backend/test/orchestrator-response-normalization.test.ts`
  Reason: pointed parser and budget tests at extracted seams instead of the monolith.
- `backend/test/scan-runtime-service.test.ts`
  Reason: added finalization-order regression coverage.

## 5. Boundary And Hardening Decisions
### Orchestrator residual risk
- Extracted: log lifecycle into `OrchestratorLogLedger`
- Extracted: budget/auth reminder behavior into `OrchestratorContextSignals`
- Extracted: fallback planning into `OrchestratorFallbackPlanner`
- Hardened in place: `OrchestratorAgent` still owns scan orchestration, but it no longer directly owns those lower-truth helper concerns

### Log pipeline / encoding path
- Hardened in place: fixed at the log-ingress boundary rather than scattering patches across DB/API/frontend
- Rejected change: no broad non-ASCII purge across prompts or the whole codebase

### Runtime-state durability
- Hardened in place: `ScanRuntimeService.stopScan()` now stops first, then captures/finalizes logs
- Hardened in place: assisted-scan finalization now uses the same agent-runtime finalization path instead of duplicating persistence
- Hardened in place: pool finalization now has an explicit helper instead of inline duplication

### BrowserService risk concentration
- Rejected change: I did not arbitrarily split `BrowserService`
- Hardened in place indirectly: browser lifecycle truth was improved by always cleaning browser sessions on orchestrator failure/completion paths and by keeping continuity verification in the browser lifecycle tests

### BurpMCPClient legacy-path risk
- Hardened in place: removed the dead legacy `scan` / issue-polling / direct-vulnerability-save path
- Rejected change: did not rewrite the active MCP tool-call path because the live path is already the correct boundary

### Stop / finalization truthfulness
- Hardened in place: `stop()` now clears paused state
- Hardened in place: runtime finalization captures the resolved terminal phase after stop ordering is correct
- Hardened in place: browser cleanup is guaranteed from failure/completion `finally` paths

### Dead / stale leftover cleanup
- Hardened in place: removed dead Burp legacy lifecycle code
- Hardened in place: moved tests off stale agent wrappers and onto real seams
- Rejected change: I did not force a broad prompt-text extraction pass because it would have been text churn with weak runtime payoff in this pass

## 6. Before Vs After Ownership / Risk Map
### Before
- `OrchestratorAgent` still mixed orchestration with visible-log persistence concerns and inline fallback/budget logic
- stop/finalization order could cache logs before terminal stop messages existed
- assisted-scan completion could persist logs twice through divergent paths
- some scan routes allowed command/live/browser/chat access before ownership was verified
- `BurpMCPClient` still carried a stale status-driving path that no longer reflected current architecture truth

### After
- visible scan-log durability and normalization live behind a single ledger boundary
- budget/auth reminders and fallback planning are again owned by extracted seams
- terminal stop behavior is more truthful: paused state clears, stop happens before final capture, and browser cleanup is guaranteed
- runtime finalization is more uniform and less duplicate-prone
- scan route access checks now match ownership expectations before side effects occur
- Burp MCP now more honestly represents a tool-call client, not a hidden scan lifecycle owner

## 7. Verification
### Commands run
- `npm.cmd run build`
- `node --import tsx --test test/orchestrator-lifecycle.test.ts test/scan-runtime-service.test.ts test/orchestrator-log-ledger.test.ts test/orchestrator-response-normalization.test.ts test/orchestrator-context-signals.test.ts test/orchestrator-fallback-planner.test.ts test/browser-visibility.test.ts test/burp-auth-regression.test.ts`
- `npm.cmd test`

### Results
- `npm.cmd run build`: passed
- focused orchestrator/runtime/browser/auth/Burp suite: failed once, then passed after correction
- `npm.cmd test`: passed, 68/68 tests green

### Failure encountered and corrected
The first focused test run failed on:
- `stop clears paused state so terminal status is truthful`

Root cause:
- `OrchestratorAgent.stop()` left `isPaused` set to `true`

Correction:
- `stop()` now explicitly clears `isPaused = false`

Re-run result:
- focused suite passed
- full backend suite passed

## 8. Regressions Checked
- visible scan-log formatting now normalizes both mojibake examples and clean Unicode markers into stable readable output
- incremental scan log flush only persists new entries
- runtime stop ordering retains terminal stop logs before caching/unregister
- scan terminal state does not remain falsely paused after stop
- browser sessions are cleaned up on orchestrator failure/completion
- browser continuity still survives manual close / stale handle / relaunch scenarios
- auth startup configuration and auth-state flows still pass
- Burp-originated auth seeding / replay / retry behavior still passes
- request execution still preserves last exchange and rate-limit pause behavior
- runtime registry behavior and log snapshot capture still pass
- full backend TypeScript build remains clean

## 9. Residual Risk
- `BrowserService` is still a large hybrid. I inspected it and kept it intact because arbitrary slicing would be fake modularization in this pass.
- `OrchestratorAgent` is still the highest-risk class in the system overall. It is safer than before, but it still coordinates many concerns.
- Burp replay prompt text is still duplicated inside `OrchestratorAgent`. I explicitly did not force a prompt-module extraction here because it was lower-value than fixing runtime truth/log durability and easy to over-refactor.
- I did not perform a giant persistence rewrite for all runtime intelligence. This pass only hardened the highest-value finalization/log durability points.
- There was a pre-existing unrelated deleted root markdown file in the working tree; I left unrelated worktree state untouched.

## 10. Final Verdict
Yes.

This pass materially reduced operational risk and improved architectural truth.

It did so by:
- moving real log, context-signal, and fallback ownership back behind extracted seams
- hardening stop/finalization ordering and browser cleanup truth
- removing a dead legacy Burp lifecycle path
- tightening route ownership checks before scan side effects
- fixing the visible agent-log encoding defect at the durable log-ingress boundary with regression coverage
