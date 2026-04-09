# PenPard Hard-Boundary Architecture Classification

## Executive Classification
PenPard is not a purely decentralized agent swarm, nor is it a simple static orchestration script. Architecturally, it is a **Domain-Specific Guided Pentest Harness** tightly coupled to a **Stateful, Auth-Aware Control Plane**, wrapped around an **LLM-Driven Diagnostic Agent**. 

Unlike generic agent platforms (e.g., LangGraph or AutoGPT), PenPard intrinsically embeds offensive security mechanics (Burp integration, finding deduplication, hypothesis tracking) directly into its orchestration and runtime components. While recent remediations have extracted tactical execution (HTTP paths) out of the central loop, the system still operates with significant, intentional overlap between Lifecycle Management (Harness) and Decision Making (Agent). 

This hard-boundary classification definitively categorizes the components to eliminate conceptual blur, demonstrating exactly where PenPard achieves strong isolation and where it relies on dangerous, role-collapsing hybrid components.

## Runtime Walkthrough by Architectural Role
1. **Scan Creation (Control Plane):** A user submits a request via `routes/scans.ts`. The Control Plane persists initial parameters to SQLite (`db/init.ts`) and creates the scan identity.
2. **Orchestrator Startup (Harness + Tool Adapter):** The `scans.ts` route asynchronously invokes the runtime engine. `ScanRuntimeService` allocates memory space and instantiates `OrchestratorAgent`.
3. **Session & Auth Seeding (Domain Engine + State):** `WebAuthStartupService` and `AuthStateManager` coordinate with `BrowserService` to resolve login credentials, store cookies, and seed the local Burp proxy.
4. **Planning Loop (Agent + Harness):** `OrchestratorAgent` requests a 5-step plan from the `LLMProviderService`. At this exact moment, it acts as the Agent (deciding what to do). When it parses the response and updates internal state machines (Phase: 'executing'), it is acting as the Harness.
5. **Tool Dispatch (Harness -> Tools):** The plan is handed to `OrchestratorToolDispatcher` and verified by `OrchestratorToolPolicy` to ensure the scope is respected.
6. **Execution (Tools + Domain Engine):** A tool like `send_http_request` is invoked. `OrchestratorRequestExecutor` (Domain Engine) intercepts this, injects auth state, and proxies the call to `BurpMCPClient` (Runtime Adapter).
7. **Finding Analysis (Domain Engine + State):** When Burp returns a result, `OrchestratorFindingTracker` deduplicates it, validates XSS/SQLi heuristics, and commits it directly to the SQLite database (Persisted State). 
8. **Re-Planning & Recheck (Agent + Domain):** Results are fed back into `HypothesisEngine` to formulate new testing paths, and `OrchestratorAgent` builds the next prompt.
9. **Pause/Stop/Finalize (Control Plane -> Harness):** If a user clicks Stop, `routes/scans.ts` signals `ScanRuntimeService` which forcefully transitions `OrchestratorAgent` into a terminal state.

---

## Strict Component Classification

- **`routes/scans.ts`**: PURE CONTROL PLANE.
- **`OrchestratorAgent.ts`**: HYBRID (HARNESS + AGENT + OVERARCHING STATE HOLDER).
- **`AgentPool.ts`**: HYBRID (HARNESS + STATE HOLDER + PERSISTENCE DISPATCHER).
- **`WorkerAgent.ts` / `RecheckAgent.ts`**: HYBRID (AGENT + HARNESS).
- **`ScanRuntimeService.ts`**: PURE HARNESS.
- **`BurpMCPClient.ts`**: PURE RUNTIME ENVIRONMENT ADAPTER.
- **`BrowserService.ts`**: HYBRID (TOOL IMPLEMENTATION + RUNTIME ADAPTER + STATE HOLDER).
- **`AuthStateManager.ts`**: HYBRID (DOMAIN ENGINE + RUNTIME STATE).
- **`RequestHarvester.ts`**: PURE DOMAIN ENGINE.
- **`HypothesisEngine.ts`**: PURE DOMAIN ENGINE.
- **`CoverageTracker.ts`**: PURE DOMAIN ENGINE.
- **`ResponseDiffer.ts`**: PURE DOMAIN ENGINE.
- **`WebAuthStartupService.ts`**: PURE DOMAIN ENGINE.
- **`LLMProviderService.ts` / `LLMQueue.ts`**: PURE RUNTIME ENVIRONMENT ADAPTER.
- **`db/init.ts`**: PURE STATE (PERSISTED) + CONTROL PLANE BACKING.
- **`OrchestratorRequestExecutor.ts`**: PURE DOMAIN ENGINE.
- **`OrchestratorFindingTracker.ts`**: HYBRID (DOMAIN ENGINE + STATE MUTATOR).

---

## Boundary Map

| Component | Primary Role | Secondary Role(s) | Why | Boundary Quality |
|-----------|--------------|-------------------|-----|------------------|
| `routes/scans.ts` | Control Plane | None | Thin HTTP routing that delegates explicitly to runtime services. | CLEAN |
| `ScanRuntimeService` | Harness | None | Manages lifecycle start, stop, and clean termination states without housing domain loop logic. | CLEAN |
| `HypothesisEngine` (and similar) | Domain Engine | None | Focused solely on security testing mechanics and heuristics, unaware of how it is executed. | CLEAN |
| `OrchestratorRequestExecutor` | Domain Engine | None | Auth injection and Burp response normalization decoupled from the main Agent logic. | CLEAN |
| `BrowserService` | Runtime Adapter | Tool Surface, State | Exposes Playwright but also holds deep in-memory session arrays and intercepts proxy traffic directly. | ACCEPTABLY HYBRID |
| `OrchestratorFindingTracker` | Domain Engine | State Persistence | Repairs vulns logically, but synchronously writes to the DB (Control Plane role) deep inside an agent loop. | ACCEPTABLY HYBRID |
| `AgentPool` | Harness | State Persistence | Intended to just manage workers, but natively listens to events and writes findings to the database. | DANGEROUSLY BLURRED |
| `OrchestratorAgent` | Agent | Harness, State | Owns the literal system prompts (Agent), phase state machines (Harness), and browser mission tracking (State). | DANGEROUSLY BLURRED |

---

## Harness vs Agent Separation

In architectural theory, the **Harness** safely runs and terminates code, while the **Agent** is pure decision-making logic. 

**PenPard DOES NOT separate these cleanly.** 
The central entity in the system, `OrchestratorAgent.ts`, is a "God Object" that embodies both.
- **True Harness Behavior:** It tracks `isRunning`, `isPaused`, catches termination signals, manages the `rateLimitPauseUntil`, handles human-in-the-loop interruption commands, and manages phase transitions.
- **True Agent Behavior:** It houses the exact 300+ line system prompt, concatenates conversation history, interprets JSON responses, and decides if it should output findings or plan execution. 

If PenPard were to adopt a generic framework (like LangGraph), the `Harness` duties of `OrchestratorAgent` would be ripped out and replaced by the framework, leaving an isolated "Plan Generator" behind. Today, PenPard has a **hybrid god object that acts as both at once**. 

`AgentPool` replicates this sin: It spins up workers (Harness), but intercepts `'vulnerability:found'` events to compute CVSS scores and flush to the DB (Domain Engine / Control Plane).

---

## Tool Surface Separation

In PenPard, the distinction between "a tool definition" (the interface) and "the tool executor" (the engine) is moderately well established, largely due to recent remediations.

- **Tool Dispatchers:** `OrchestratorToolDispatcher` is a pure tool mediator. It maps LLM JSON to strict typescript handlers.
- **Tool Policies:** `OrchestratorToolPolicy` serves as a semantic firewall enforcing operator boundaries.
- **Tool Implementations:** Tools themselves do not live in the Agent. They are forwarded. 
  - `send_http_request` goes to `OrchestratorRequestExecutor`
  - `send_to_scanner` goes to `BurpMCPClient` 
  - `browser_navigate` goes to `BrowserService`

**The Verdict:** The tool registry is explicit and nicely separated. PenPard no longer suffers from the Agent directly implementing the HTTP stack. However, `BrowserService` is incorrectly acting as a State Holder when invoked as a Tool, as it secretly stockpiles JS artifacts and network traffic.

---

## Control Plane Separation

The Control Plane resides primarily in Express routing (`routes/*.ts`) and persistent SQLite operations (`db/init.ts`). 

- **Scan Governance:** Cleanly isolated in `routes/scans.ts` and `routes/status.ts`.
- **Status Transitions:** Mediated strictly by `ScanRuntimeService`. Previously, the Orchestrator could misreport itself, but the boundary remediation forced finalization to be resolved by the Runtime entity, successfully locking the Agent out of the Control Plane.
- **Persistence Hooks:** The Control Plane logic writes purely to SQLite.
- **Boundary Leak:** The only major leakage of Control Plane behavior occurs when runtime entities deep in the execution stack (`OrchestratorFindingTracker`, `AgentPool`) reach over and perform direct `addVulnerability` database calls, bypassing the formal Control Plane API.

---

## State Separation

State in PenPard is scattered and suffers from strict conceptual overlap.

**1. Persisted State (Durable):**
- SQLite houses `scans`, `vulnerabilities`, `reports`, `browser_sessions`. 
- **Quality:** Clean and resilient.

**2. In-Memory Runtime State (Volatile):**
- Maps inside `ScanRuntimeService` holding class instances.
- Internal Maps in `BrowserService` (`sessions: Map<string, LiveSession>`). 
- **Quality:** Dangerously trapped inside process memory. If the Node process crashes, `BrowserService` loses all JS-artifacts and proxy traffic logs, forcing a complex recovery.

**3. Ephemeral Execution State (Cross-Round):**
- `OrchestratorAgent` holds `discoveredEndpoints`, `findings`, `conversationHistory`.
- **Quality:** Blurry. Some states are flushed (logs), but the raw conversation history is trapped. If the system is paused and resumed, it relies on partial database hydration to reconstruct the `OrchestratorAgent` memory.

---

## Domain Engine Separation

What makes PenPard a "pentesting" product rather than a generic LangChain chat bot? 

The **Domain Engine** consists of:
- **Auth-Aware Logic:** `WebAuthStartupService`, `AuthStateManager`, `OrchestratorRequestExecutor` (auto-token injection, 401 recovery).
- **Burp-Mediated Logic:** `BurpMCPClient`.
- **Heuristic Engines:** `HypothesisEngine` (predictive vulnerability theories), `CoverageTracker`, `RequestHarvester`, `ResponseDiffer`. 

If you removed this entirely, the remaining skeleton is just: An Express server that takes a request, launches an LLM loop, logs output, and stops.

The Domain Engine is PenPard's primary moat. Architecturally, it is the most successfully isolated tier in the system. Components like `HypothesisEngine` and `CoverageTracker` export pure domain value without touching the database or the network.

---

## Runtime Environment Separation

PenPard's runtime environment comprises:
- An operator machine (Node process).
- Local Burp Suite Instance (interacted via MCP).
- Local Chromium Process (controlled via Playwright).
- Local SQLite Database.
- Networked HTTP LLM APIs (OpenAI / Anthropic).

**Is PenPard's runtime abstract and portable, or concretely bound?**
It is extremely, concretely bound to the local pentest dependencies. Code assumes native `child_process` spawn capabilities. `BrowserService` directly interacts with the local disk for user data directories. `BurpMCPClient` assumes Burp is running adjacent to it. PenPard is NOT a floating cloud lambda; it is a heavy, desktop-linked runtime environment.

---

## God Objects and Hybrid Zones

### 1. `OrchestratorAgent.ts`
- **Roles:** Agent + Harness + Ephemeral State Holder
- **Why it is expensive:** Because the LLM prompt construction (Agent) and the `rateLimitPause` timeouts (Harness) live in the same file. To change how the system scales out across nodes, you have to modify the file that dictates how the AI formulates SQL injection plans.
- **Origin:** Strategic/Legacy. It grew out of a monolithic script and, as noted in the recent Walkthrough, forcing a separation today would result in "fake modularity" with an over-reliance on callbacks.

### 2. `AgentPool.ts`
- **Roles:** Harness + State Persister
- **Why it is expensive:** It is supposed to just distribute targets to `WorkerAgent`s. Instead, it natively dictates the logic for converting raw Agent JSON into formatted SQLite database structures and calculates CVSS scores. If an operator wants to change how severity translates to CVSS, they have to modify the orchestration pool. 

### 3. `BrowserService.ts`
- **Roles:** Tool Endpoint + Environment Adapter + State Holder
- **Why it is expensive:** It bridges Playwright APIs, maintains live process memory, manages UI visibility, and tracks traffic events. Because it holds deep `LiveSession` state, it is inherently monolithic, trapping session data if the process restarts.

---

## Final Hard Classification

- PenPard is a **domain-specific pentest orchestration platform securely wrapped around an LLM execution loop.**
- It is not **a generic agent framework**, nor is it **a simple wrapper script.**
- Its harness is **interwoven tightly with the Agent, represented primarily by `ScanRuntimeService` scaling `OrchestratorAgent`.**
- Its agent is **the internal iteration loop of `OrchestratorAgent` driven by `LLMProviderService`.**
- Its control plane is **the Express layer mapping API commands into SQLite and instructing the Harness.**
- Its domain engine is **the powerful, isolated suite of security heuristics (`HypothesisEngine`, `CoverageTracker`, `RequestHarvester`).**
- Its tool surface is **mediated via `OrchestratorToolDispatcher` and routed to the Domain Engine and Runtime Environment.**
- Its runtime environment is **heavy, local, desktop-bound, relying intrinsically on Playwright and Burp Suite.**
- Its main architectural blur is **the god-object overlap between deciding what to test (Agent) and managing the lifecycle of the test (Harness) within `OrchestratorAgent` and `AgentPool`.**
- Its main architectural strength is **the strict separation of its Domain Engine, which extracts complex security reasoning into highly testable, standalone modules oblivious to orchestration mechanics.**

## Appendix: Evidence Inventory
1. `backend/src/agents/OrchestratorAgent.ts`: Houses 300+ line system prompts alongside timeout structures and human-in-the-loop processing queues.
2. `backend/src/agents/AgentPool.ts`: Lines `context.on('vulnerability:found')` invoke database-writing logic and CVSS scoring.
3. `backend/src/services/BrowserService.ts`: Holds heavily nested `LiveSession` maps and intercepts proxy traffic arrays directly in memory.
4. `backend/src/routes/scans.ts`: Acts strictly as a Control Plane surface without touching domain pentesting methodologies.
5. Remediations noted in `orchestrator-boundary-remediation-walkthrough.md` validate that `OrchestratorRequestExecutor` and `OrchestratorFindingTracker` successfully removed Tool and DB implementations from the direct Agent flow.
