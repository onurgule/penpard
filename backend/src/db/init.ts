import Database, { Database as DatabaseType } from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { logger } from '../utils/logger';
import type { BrowserLifecycleState } from '../types/browserLifecycle';
import type {
  DiscoveredRequestRef,
  EvidenceBundle,
  FocusedCaseFinding,
  FocusedConfirmationKind,
  FocusedConfirmationState,
  FocusedConfirmationStep,
  FocusedCaseHistoricalCompare,
  FocusedCaseInvestigationSummary,
  FocusedCaseVerdict,
  FocusedFindingThread,
  FocusedFindingStatus,
  FocusedExecutionTraceEntry,
  FocusedReasoningTraceEntry,
  ScopedBrowserAnchorRef,
  ScopedFeatureDiscoveryState,
  FocusedHistoricalCompareState,
  FocusedHistoricalCompareSummary,
  FocusedEvidenceSufficiencyReport,
  FocusedSignalInterpretationSummary,
  FocusedInvestigationIssue,
  FocusedRemovedHistoricalCase,
  FocusedScanFindingSummary,
  FocusedTestCase,
  FocusedTestCaseExecution,
  FocusedExecutionSummary,
  FocusedScanBlockerSummary,
  FocusedScanVerdictSummary,
  FocusedSupportProvenanceSummary,
  FocusedTestObjective,
  FocusedRequestEvidenceStory,
  ScopeEnvelope,
  ScanMode,
  StructuredSecurityTestRequest,
} from '../services/runtime/ScopedScanTypes';
import {
  applyFocusedCaseVerdict,
  applyFocusedCaseFindings,
  applyFocusedExecutionSummary,
  applyFocusedFindingThreads,
  applyFocusedHistoricalCompare,
  applyFocusedInvestigationSummary,
  buildFocusedRailUsageSummary,
  createEmptyFocusedBlockerRecurrenceSummary,
  createEmptyFocusedFindingStatusCounts,
  createEmptyFocusedInvestigationImpactCounts,
  createEmptyFocusedInvestigationStatusCounts,
  createEmptyFocusedInvestigationTypeCounts,
  createEmptyFocusedVerdictCounts,
  createEmptyFocusedVerdictTransitionCounts,
  deriveFocusedExecutionPresentationState,
  normalizeFocusedCaseCompareStatus,
  normalizeFocusedCaseFamily,
  normalizeFocusedCaseIntelligence,
  normalizeFocusedEvidenceSufficiencyState,
  normalizeFocusedEvidenceDriftClassification,
  normalizeFocusedEvidenceReasoningEffect,
  normalizeFocusedFindingConfidenceBand,
  normalizeFocusedFindingStatus,
  normalizeFocusedFindingThreadStatus,
  normalizeFocusedConfirmationKind,
  normalizeFocusedConfirmationReadiness,
  normalizeFocusedConfirmationStepStatus,
  normalizeFocusedExecutionPresentationState,
  normalizeFocusedExecutionRail,
  normalizeFocusedExecutionState,
  normalizeFocusedExecutionTraceActionType,
  normalizeFocusedHistoricalCompareStatus,
  normalizeFocusedHistoricalOutcome,
  normalizeFocusedHypothesisStatus,
  normalizeFocusedInvestigationImpact,
  normalizeFocusedInvestigationIssueStatus,
  normalizeFocusedInvestigationIssueType,
  normalizeFocusedOverallChangeClassification,
  normalizeFocusedReasoningContextEffect,
  normalizeFocusedReasoningEntryType,
  normalizeFocusedReasoningRail,
  normalizeFocusedReasoningStage,
  normalizeFocusedRequestContextField,
  normalizeScopedFeatureDiscoveryOutcome,
  normalizeScopedFeatureDiscoveryPhase,
  normalizeFocusedSignalMarker,
  normalizeFocusedSignalSuspiciousness,
  normalizeFocusedSuspicionProofStatus,
  normalizeFocusedWorkaroundOutcome,
  normalizeFocusedVerdictState,
  normalizeFocusedVerdictTransition,
  isFocusedInvestigationIssueUnresolved,
} from '../services/runtime/ScopedScanTypes';

// Get consistent database path across CLI, Electron, and standalone backend
function getDefaultDbPath(): string {
  let appDataPath: string;

  if (process.platform === 'win32') {
    appDataPath = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  } else if (process.platform === 'darwin') {
    appDataPath = path.join(os.homedir(), 'Library', 'Application Support');
  } else {
    appDataPath = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  }

  return path.join(appDataPath, 'penpard', 'data', 'penpard.db');
}

const DB_PATH = process.env.DATABASE_PATH || getDefaultDbPath();

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

export const db: DatabaseType = new Database(DB_PATH);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

export async function initDatabase(): Promise<void> {
  logger.info('Initializing database...');
  console.log(`📁 Database path: ${DB_PATH}`);

  // Create tables
  db.exec(`
    -- Users table
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('super_admin', 'admin', 'user')),
      credits INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Whitelists table
    CREATE TABLE IF NOT EXISTS whitelists (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      domain_pattern TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- LLM Configuration table
    CREATE TABLE IF NOT EXISTS llm_config (
        provider TEXT PRIMARY KEY,
        api_key TEXT,
        model TEXT,
        is_active INTEGER DEFAULT 0,
        is_online INTEGER DEFAULT 0,
        settings_json TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- MCP Servers table
    CREATE TABLE IF NOT EXISTS mcp_servers (
        name TEXT PRIMARY KEY,
        command TEXT NOT NULL,
        args TEXT,
        env_vars TEXT,
        status TEXT DEFAULT 'stopped',
        is_enabled INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Settings table (key-value store for prompts, logo path, etc.)
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Scans table
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('web', 'mobile')),
      scan_mode TEXT NOT NULL DEFAULT 'exploratory' CHECK(scan_mode IN ('exploratory', 'scoped')),
      target TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      burp_scan_id TEXT,
      mobsf_hash TEXT,
      
      -- New Antigravity Fields
      llm_provider TEXT,
      rate_limit INTEGER DEFAULT 5,
      recursion_depth INTEGER DEFAULT 2,
      use_nuclei INTEGER DEFAULT 0,
      use_ffuf INTEGER DEFAULT 0,
      idor_users_json TEXT,
      orchestrator_logs_path TEXT,

      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME,
      error_message TEXT,
      scan_config_json TEXT,
      auth_inventory_json TEXT,
      endpoint_inventory_json TEXT,
      runtime_checkpoint_json TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_test_objectives (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL UNIQUE,
      title TEXT NOT NULL,
      scope_type TEXT NOT NULL CHECK(scope_type IN ('request_scoped', 'endpoint_scoped', 'flow_scoped', 'feature_scoped')),
      feature_description TEXT,
      goal TEXT,
      operator_notes TEXT,
      risk_tags_json TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scope_envelopes (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL UNIQUE,
      version INTEGER NOT NULL DEFAULT 1,
      allowed_hosts_json TEXT,
      allowed_routes_json TEXT,
      selected_endpoints_json TEXT,
      baseline_request_refs_json TEXT,
      discovered_request_refs_json TEXT,
      browser_anchors_json TEXT,
      request_bundle_refs_json TEXT,
      auth_context_json TEXT,
      out_of_scope_notes_json TEXT,
      boundary_hints_json TEXT,
      exploration_budget_json TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scoped_test_requests (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL UNIQUE,
      target_url TEXT NOT NULL,
      description TEXT NOT NULL,
      environment TEXT,
      service_name TEXT,
      test_data_json TEXT,
      test_users_json TEXT,
      login_present INTEGER,
      auth_mechanism_hints_json TEXT,
      has_screenshot_or_attachment INTEGER,
      attachment_metadata_json TEXT,
      attachment_summary TEXT,
      new_screen_count INTEGER,
      new_input_count INTEGER,
      operator_notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scoped_feature_discovery_states (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL UNIQUE,
      phase TEXT NOT NULL CHECK(phase IN ('not_started', 'discovering', 'ready_to_plan', 'blocked')),
      outcome TEXT CHECK(outcome IN ('candidate_anchors_found', 'partial_anchors_found', 'no_useful_anchors')),
      summary TEXT,
      error_message TEXT,
      request_anchor_count INTEGER NOT NULL DEFAULT 0,
      browser_anchor_count INTEGER NOT NULL DEFAULT 0,
      selected_endpoint_count INTEGER NOT NULL DEFAULT 0,
      allowed_route_count INTEGER NOT NULL DEFAULT 0,
      started_at DATETIME,
      completed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_test_cases (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      title TEXT NOT NULL,
      hypothesis TEXT NOT NULL,
      target_artifact_json TEXT NOT NULL,
      preconditions_json TEXT NOT NULL,
      steps_json TEXT NOT NULL,
      assertions_json TEXT NOT NULL,
      required_evidence_json TEXT NOT NULL,
      priority TEXT NOT NULL CHECK(priority IN ('high', 'medium', 'low')),
      planner_rationale_summary TEXT NOT NULL,
      case_family TEXT NOT NULL DEFAULT 'generic' CHECK(case_family IN ('generic', 'sqli', 'xss', 'access_control', 'input_validation', 'error_handling', 'workflow_logic')),
      case_intelligence_json TEXT NOT NULL DEFAULT '{}',
      max_adaptive_follow_ups INTEGER NOT NULL DEFAULT 1,
      preferred_rail TEXT NOT NULL DEFAULT 'request' CHECK(preferred_rail IN ('system', 'request', 'browser', 'hybrid')),
      allowed_confirmation_kinds_json TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'planned' CHECK(status IN ('planned', 'disabled')),
      review_state TEXT NOT NULL DEFAULT 'pending_review' CHECK(review_state IN ('pending_review', 'approved', 'rejected')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (objective_id) REFERENCES focused_test_objectives(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_test_case_executions (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      case_id TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      execution_state TEXT NOT NULL CHECK(execution_state IN ('ready', 'running', 'completed', 'blocked', 'failed_to_execute', 'skipped')),
      execution_profile_key TEXT NOT NULL,
      run_reason TEXT,
      notes_summary TEXT,
      error_message TEXT,
      request_actions_used INTEGER NOT NULL DEFAULT 0,
      browser_actions_used INTEGER NOT NULL DEFAULT 0,
      browser_session_id TEXT,
      started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (case_id) REFERENCES focused_test_cases(id) ON DELETE CASCADE,
      FOREIGN KEY (objective_id) REFERENCES focused_test_objectives(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_test_case_execution_trace_entries (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      case_id TEXT NOT NULL,
      execution_id TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      action_type TEXT NOT NULL,
      action_summary TEXT NOT NULL,
      target_summary TEXT,
      request_summary_json TEXT,
      response_summary_json TEXT,
      reasoning_note TEXT,
      next_step_rationale TEXT,
      stop_reason TEXT,
      retry_reason TEXT,
      rail TEXT NOT NULL DEFAULT 'system',
      tool_summary TEXT,
      linked_evidence_ids_json TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (case_id) REFERENCES focused_test_cases(id) ON DELETE CASCADE,
      FOREIGN KEY (execution_id) REFERENCES focused_test_case_executions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_reasoning_trace_entries (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      case_id TEXT,
      execution_id TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      stage TEXT NOT NULL,
      entry_type TEXT NOT NULL,
      rail TEXT NOT NULL DEFAULT 'system_only',
      case_family TEXT,
      summary TEXT NOT NULL,
      observation_summary TEXT,
      hypothesis_rationale_summary TEXT,
      action_selection_rationale TEXT,
      request_response_impact_summary TEXT,
      browser_state_impact_summary TEXT,
      confidence_shift_summary TEXT,
      stop_retry_block_rationale TEXT,
      linked_evidence_ids_json TEXT,
      linked_request_context_keys_json TEXT,
      context_influence_json TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (objective_id) REFERENCES focused_test_objectives(id) ON DELETE CASCADE,
      FOREIGN KEY (case_id) REFERENCES focused_test_cases(id) ON DELETE CASCADE,
      FOREIGN KEY (execution_id) REFERENCES focused_test_case_executions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_test_case_evidence_bundles (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      case_id TEXT NOT NULL,
      execution_id TEXT NOT NULL,
      summary TEXT NOT NULL,
      source TEXT NOT NULL,
      captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      request_ref_json TEXT,
      response_ref_json TEXT,
      response_diff_summary_json TEXT,
      screenshot_ref_json TEXT,
      browser_state_json TEXT,
      related_evidence_ids_json TEXT,
      execution_notes TEXT,
      provenance_json TEXT,
      scope_violation_json TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (case_id) REFERENCES focused_test_cases(id) ON DELETE CASCADE,
      FOREIGN KEY (execution_id) REFERENCES focused_test_case_executions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_test_case_verdicts (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      case_id TEXT NOT NULL,
      execution_id TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      verdict_state TEXT NOT NULL CHECK(verdict_state IN ('pass', 'fail', 'inconclusive', 'needs_review')),
      verdict_reason TEXT NOT NULL,
      evidence_sufficiency_state TEXT NOT NULL CHECK(evidence_sufficiency_state IN ('sufficient', 'insufficient', 'contradictory', 'unsupported')),
      evidence_sufficiency_report_json TEXT NOT NULL,
      supporting_evidence_refs_json TEXT NOT NULL,
      support_provenance_json TEXT,
      request_evidence_story_json TEXT,
      interpretation_summary_json TEXT,
      scope_violation_impact_json TEXT,
      execution_snapshot_json TEXT NOT NULL,
      assistance_profile_key TEXT,
      assistance_provider TEXT,
      assistance_model TEXT,
      assistance_narrative TEXT,
      verdict_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(scan_id, case_id, execution_id),
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (case_id) REFERENCES focused_test_cases(id) ON DELETE CASCADE,
      FOREIGN KEY (execution_id) REFERENCES focused_test_case_executions(id) ON DELETE CASCADE,
      FOREIGN KEY (objective_id) REFERENCES focused_test_objectives(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_test_case_findings (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      case_id TEXT NOT NULL,
      execution_id TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      finding_key TEXT NOT NULL,
      title TEXT NOT NULL,
      family TEXT NOT NULL CHECK(family IN ('generic', 'sqli', 'xss', 'access_control', 'input_validation', 'error_handling', 'workflow_logic')),
      status TEXT NOT NULL CHECK(status IN ('confirmed', 'likely', 'suspicious', 'inconclusive', 'not_confirmed')),
      suspicion_score INTEGER NOT NULL DEFAULT 0,
      confirmation_progress INTEGER NOT NULL DEFAULT 0,
      confidence_band TEXT NOT NULL CHECK(confidence_band IN ('low', 'medium', 'high')),
      rank_order INTEGER NOT NULL DEFAULT 0,
      is_primary INTEGER NOT NULL DEFAULT 0,
      strongest_support_summary TEXT NOT NULL,
      blocking_constraint_summary TEXT,
      next_step_summary TEXT,
      supporting_signals_json TEXT NOT NULL,
      blocking_constraints_json TEXT NOT NULL,
      supporting_evidence_refs_json TEXT NOT NULL,
      support_provenance_json TEXT,
      request_evidence_story_json TEXT,
      linked_verdict_ids_json TEXT NOT NULL,
      linked_investigation_ids_json TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(scan_id, case_id, execution_id, finding_key),
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (case_id) REFERENCES focused_test_cases(id) ON DELETE CASCADE,
      FOREIGN KEY (execution_id) REFERENCES focused_test_case_executions(id) ON DELETE CASCADE,
      FOREIGN KEY (objective_id) REFERENCES focused_test_objectives(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_test_case_finding_threads (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      case_id TEXT NOT NULL,
      execution_id TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      finding_key TEXT NOT NULL,
      title TEXT NOT NULL,
      family TEXT NOT NULL CHECK(family IN ('generic', 'sqli', 'xss', 'access_control', 'input_validation', 'error_handling', 'workflow_logic')),
      status TEXT NOT NULL CHECK(status IN ('collecting', 'strengthening', 'confirming', 'blocked', 'exhausted', 'published')),
      suspicion_score INTEGER NOT NULL DEFAULT 0,
      confirmation_progress INTEGER NOT NULL DEFAULT 0,
      confidence_band TEXT NOT NULL CHECK(confidence_band IN ('low', 'medium', 'high')),
      is_primary INTEGER NOT NULL DEFAULT 0,
      strongest_support_summary TEXT,
      strongest_suspicious_signal TEXT,
      strongest_blocker_summary TEXT,
      next_step_summary TEXT,
      stop_reason TEXT,
      supporting_signals_json TEXT NOT NULL,
      blocking_constraints_json TEXT NOT NULL,
      supporting_evidence_refs_json TEXT NOT NULL,
      blocking_evidence_refs_json TEXT NOT NULL,
      support_provenance_json TEXT,
      request_evidence_story_json TEXT,
      linked_trace_ids_json TEXT NOT NULL,
      linked_verdict_ids_json TEXT NOT NULL,
      linked_investigation_ids_json TEXT NOT NULL,
      confirmation_state_json TEXT NOT NULL,
      published_finding_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(scan_id, case_id, execution_id, finding_key),
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (case_id) REFERENCES focused_test_cases(id) ON DELETE CASCADE,
      FOREIGN KEY (execution_id) REFERENCES focused_test_case_executions(id) ON DELETE CASCADE,
      FOREIGN KEY (objective_id) REFERENCES focused_test_objectives(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_scan_verdict_summaries (
      scan_id TEXT PRIMARY KEY,
      objective_id TEXT NOT NULL,
      overall_verdict TEXT NOT NULL CHECK(overall_verdict IN ('pass', 'fail', 'inconclusive', 'needs_review')),
      total_cases INTEGER NOT NULL DEFAULT 0,
      counts_by_verdict_json TEXT NOT NULL,
      manual_review_recommended INTEGER NOT NULL DEFAULT 0,
      major_blockers_json TEXT NOT NULL,
      latest_verdict_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (objective_id) REFERENCES focused_test_objectives(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_test_case_investigation_issues (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      case_id TEXT NOT NULL,
      execution_id TEXT NOT NULL,
      objective_id TEXT NOT NULL,
      issue_type TEXT NOT NULL CHECK(issue_type IN (
        'scope_violation',
        'auth_session_drift',
        'missing_anchor',
        'browser_state_mismatch',
        'evidence_insufficient',
        'execution_budget_exhausted',
        'request_replay_mismatch',
        'unexpected_navigation',
        'unsupported_verification_primitive',
        'environment_instability',
        'contradictory_signals',
        'retry_failure',
        'blocked_flow'
      )),
      issue_title TEXT NOT NULL,
      issue_details TEXT,
      issue_status TEXT NOT NULL CHECK(issue_status IN ('open', 'resolved', 'partially_resolved', 'unresolved', 'not_applicable')),
      impact TEXT NOT NULL CHECK(impact IN ('informational', 'degrading', 'blocking')),
      source TEXT NOT NULL DEFAULT 'system' CHECK(source IN ('system', 'profile_assistance', 'operator')),
      correlation_json TEXT,
      linked_evidence_ids_json TEXT,
      linked_verdict_ids_json TEXT,
      workaround_attempts_json TEXT,
      expert_followup_hint TEXT,
      assistance_summary TEXT,
      assistance_profile_key TEXT,
      assistance_provider TEXT,
      assistance_model TEXT,
      detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      resolved_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (case_id) REFERENCES focused_test_cases(id) ON DELETE CASCADE,
      FOREIGN KEY (execution_id) REFERENCES focused_test_case_executions(id) ON DELETE CASCADE,
      FOREIGN KEY (objective_id) REFERENCES focused_test_objectives(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_scan_blocker_summaries (
      scan_id TEXT PRIMARY KEY,
      objective_id TEXT NOT NULL,
      counts_by_status_json TEXT NOT NULL,
      counts_by_impact_json TEXT NOT NULL,
      unresolved_by_type_json TEXT NOT NULL,
      repeated_blockers_json TEXT NOT NULL,
      cases_needing_review_json TEXT NOT NULL,
      latest_major_blocker_summary TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (objective_id) REFERENCES focused_test_objectives(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS focused_scan_historical_compare_states (
      scan_id TEXT PRIMARY KEY,
      scope_type TEXT NOT NULL CHECK(scope_type IN ('request_scoped', 'endpoint_scoped', 'flow_scoped', 'feature_scoped')),
      target_origin TEXT NOT NULL,
      scope_identity_key TEXT NOT NULL,
      comparison_status TEXT NOT NULL CHECK(comparison_status IN ('comparison_unavailable', 'baseline_created', 'compared', 'not_comparable')),
      baseline_scan_id TEXT,
      compared_against_scan_id TEXT,
      first_observed_at DATETIME,
      latest_compare_at DATETIME,
      status_reason TEXT,
      assistance_profile_key TEXT,
      assistance_provider TEXT,
      assistance_model TEXT,
      assistance_narrative TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (baseline_scan_id) REFERENCES scans(id) ON DELETE SET NULL,
      FOREIGN KEY (compared_against_scan_id) REFERENCES scans(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS focused_test_case_historical_compares (
      id TEXT PRIMARY KEY,
      current_scan_id TEXT NOT NULL,
      current_case_id TEXT NOT NULL,
      current_execution_id TEXT,
      case_identity_key TEXT NOT NULL,
      case_variant_key TEXT NOT NULL,
      previous_scan_id TEXT,
      previous_case_id TEXT,
      previous_execution_id TEXT,
      compare_status TEXT NOT NULL CHECK(compare_status IN ('baseline_only', 'exact_match', 'likely_match', 'newly_introduced', 'not_comparable')),
      historical_outcome TEXT CHECK(historical_outcome IN ('improved', 'regressed', 'unchanged', 'weaker_confidence', 'stronger_confidence', 'newly_introduced', 'not_comparable')),
      prior_verdict TEXT CHECK(prior_verdict IN ('pass', 'fail', 'inconclusive', 'needs_review')),
      current_verdict TEXT CHECK(current_verdict IN ('pass', 'fail', 'inconclusive', 'needs_review')),
      verdict_transition TEXT CHECK(verdict_transition IN (
        'pass_to_pass',
        'pass_to_fail',
        'pass_to_inconclusive',
        'pass_to_needs_review',
        'fail_to_pass',
        'fail_to_fail',
        'fail_to_inconclusive',
        'fail_to_needs_review',
        'inconclusive_to_pass',
        'inconclusive_to_fail',
        'inconclusive_to_inconclusive',
        'inconclusive_to_needs_review',
        'needs_review_to_pass',
        'needs_review_to_fail',
        'needs_review_to_inconclusive',
        'needs_review_to_needs_review'
      )),
      prior_evidence_sufficiency TEXT CHECK(prior_evidence_sufficiency IN ('sufficient', 'insufficient', 'contradictory', 'unsupported')),
      current_evidence_sufficiency TEXT CHECK(current_evidence_sufficiency IN ('sufficient', 'insufficient', 'contradictory', 'unsupported')),
      prior_verdict_reason TEXT,
      current_verdict_reason TEXT,
      prior_evidence_summary TEXT,
      current_evidence_summary TEXT,
      evidence_drift_classification TEXT CHECK(evidence_drift_classification IN (
        'unchanged',
        'stronger_confidence',
        'weaker_confidence',
        'unsupported_gap_introduced',
        'contradiction_introduced',
        'scope_risk_increased'
      )),
      blocker_recurrence_json TEXT NOT NULL,
      compare_narrative TEXT,
      assistance_profile_key TEXT,
      assistance_provider TEXT,
      assistance_model TEXT,
      latest_compare_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(current_scan_id, current_case_id),
      FOREIGN KEY (current_scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (current_case_id) REFERENCES focused_test_cases(id) ON DELETE CASCADE,
      FOREIGN KEY (current_execution_id) REFERENCES focused_test_case_executions(id) ON DELETE SET NULL,
      FOREIGN KEY (previous_scan_id) REFERENCES scans(id) ON DELETE SET NULL,
      FOREIGN KEY (previous_case_id) REFERENCES focused_test_cases(id) ON DELETE SET NULL,
      FOREIGN KEY (previous_execution_id) REFERENCES focused_test_case_executions(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS focused_scan_historical_compare_summaries (
      scan_id TEXT PRIMARY KEY,
      baseline_scan_id TEXT,
      compared_against_scan_id TEXT,
      comparison_status TEXT NOT NULL CHECK(comparison_status IN ('comparison_unavailable', 'baseline_created', 'compared', 'not_comparable')),
      overall_change_classification TEXT NOT NULL CHECK(overall_change_classification IN ('baseline_only', 'improvement', 'regression', 'instability', 'no_material_change')),
      counts_by_verdict_transition_json TEXT NOT NULL,
      improved_count INTEGER NOT NULL DEFAULT 0,
      regressed_count INTEGER NOT NULL DEFAULT 0,
      unchanged_count INTEGER NOT NULL DEFAULT 0,
      weaker_confidence_count INTEGER NOT NULL DEFAULT 0,
      stronger_confidence_count INTEGER NOT NULL DEFAULT 0,
      newly_introduced_count INTEGER NOT NULL DEFAULT 0,
      not_comparable_count INTEGER NOT NULL DEFAULT 0,
      removed_prior_case_count INTEGER NOT NULL DEFAULT 0,
      improved_cases_json TEXT NOT NULL,
      regressed_cases_json TEXT NOT NULL,
      unstable_cases_json TEXT NOT NULL,
      repeated_blocker_families_json TEXT NOT NULL,
      new_blocker_families_json TEXT NOT NULL,
      resolved_blocker_families_json TEXT NOT NULL,
      removed_prior_cases_json TEXT NOT NULL,
      stability_notes_json TEXT NOT NULL,
      manual_review_recommended INTEGER NOT NULL DEFAULT 0,
      latest_compare_at DATETIME,
      assistance_profile_key TEXT,
      assistance_provider TEXT,
      assistance_model TEXT,
      compare_narrative TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (baseline_scan_id) REFERENCES scans(id) ON DELETE SET NULL,
      FOREIGN KEY (compared_against_scan_id) REFERENCES scans(id) ON DELETE SET NULL
    );

    -- Vulnerabilities table
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      severity TEXT NOT NULL,
      cvss_score REAL,
      cvss_vector TEXT,
      cwe TEXT,
      cve TEXT,
      request TEXT,
      response TEXT,
      screenshot_path TEXT,
      evidence TEXT,
      remediation TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    -- Reports table
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT UNIQUE NOT NULL,
      file_path TEXT NOT NULL,
      format TEXT DEFAULT 'markdown',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    -- Canonical deterministic report snapshots
    CREATE TABLE IF NOT EXISTS report_snapshots (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      report_json TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(scan_id, fingerprint),
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    -- Persisted export jobs for report artifacts
    CREATE TABLE IF NOT EXISTS report_exports (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      snapshot_id TEXT NOT NULL,
      snapshot_fingerprint TEXT NOT NULL,
      format TEXT NOT NULL CHECK(format IN ('pdf', 'docx', 'pptx')),
      enrichment_mode TEXT NOT NULL CHECK(enrichment_mode IN ('deterministic', 'llm')),
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed', 'canceled')),
      stage TEXT NOT NULL DEFAULT 'queued'
        CHECK(stage IN ('idle', 'queued', 'collecting_data', 'composing_report', 'enriching_with_llm', 'rendering_export', 'completed', 'failed', 'canceled')),
      llm_status TEXT NOT NULL DEFAULT 'not_requested'
        CHECK(llm_status IN ('not_requested', 'queued', 'running', 'completed', 'failed', 'skipped')),
      artifact_path TEXT,
      resolved_report_json TEXT,
      error_message TEXT,
      llm_error_message TEXT,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      started_at DATETIME,
      completed_at DATETIME,
      canceled_at DATETIME,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
      FOREIGN KEY (snapshot_id) REFERENCES report_snapshots(id) ON DELETE CASCADE
    );

    -- Token usage tracking table
    CREATE TABLE IF NOT EXISTS token_usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT NOT NULL,
      model TEXT NOT NULL,
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      total_tokens INTEGER NOT NULL DEFAULT 0,
      reasoning_tokens INTEGER NOT NULL DEFAULT 0,
      scan_id TEXT,
      report_export_id TEXT,
      context TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Scan logs table (persists agent logs for completed scans)
    CREATE TABLE IF NOT EXISTS scan_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    -- Scan chat messages (persists human commands + PenPard responses)
    CREATE TABLE IF NOT EXISTS scan_chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('human', 'assistant')),
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    -- Create indexes
    CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
    CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
    CREATE INDEX IF NOT EXISTS idx_whitelists_user_id ON whitelists(user_id);
    CREATE INDEX IF NOT EXISTS idx_report_snapshots_scan_id ON report_snapshots(scan_id);
    CREATE INDEX IF NOT EXISTS idx_report_snapshots_fingerprint ON report_snapshots(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_report_exports_scan_id ON report_exports(scan_id);
    CREATE INDEX IF NOT EXISTS idx_report_exports_status_stage ON report_exports(status, stage);
    CREATE INDEX IF NOT EXISTS idx_report_exports_snapshot_format ON report_exports(snapshot_id, format, enrichment_mode);
    CREATE INDEX IF NOT EXISTS idx_token_usage_created_at ON token_usage(created_at);
    CREATE INDEX IF NOT EXISTS idx_token_usage_provider_model ON token_usage(provider, model);
    CREATE INDEX IF NOT EXISTS idx_scan_logs_scan_id ON scan_logs(scan_id);
    CREATE INDEX IF NOT EXISTS idx_scan_chat_messages_scan_id ON scan_chat_messages(scan_id);
CREATE INDEX IF NOT EXISTS idx_focused_test_objectives_scan_id ON focused_test_objectives(scan_id);
CREATE INDEX IF NOT EXISTS idx_scope_envelopes_scan_id ON scope_envelopes(scan_id);
CREATE INDEX IF NOT EXISTS idx_scoped_test_requests_scan_id ON scoped_test_requests(scan_id);
CREATE INDEX IF NOT EXISTS idx_scoped_feature_discovery_states_scan_id ON scoped_feature_discovery_states(scan_id);
CREATE INDEX IF NOT EXISTS idx_focused_test_cases_scan_id ON focused_test_cases(scan_id);
CREATE INDEX IF NOT EXISTS idx_focused_test_cases_objective_id ON focused_test_cases(objective_id);
CREATE INDEX IF NOT EXISTS idx_focused_test_case_executions_scan_id ON focused_test_case_executions(scan_id);
CREATE INDEX IF NOT EXISTS idx_focused_test_case_executions_case_id ON focused_test_case_executions(case_id);
CREATE INDEX IF NOT EXISTS idx_focused_test_case_executions_execution_state ON focused_test_case_executions(execution_state);
    CREATE INDEX IF NOT EXISTS idx_focused_execution_trace_scan_id ON focused_test_case_execution_trace_entries(scan_id);
    CREATE INDEX IF NOT EXISTS idx_focused_execution_trace_case_id ON focused_test_case_execution_trace_entries(case_id);
    CREATE INDEX IF NOT EXISTS idx_focused_execution_trace_execution_id ON focused_test_case_execution_trace_entries(execution_id);
    CREATE INDEX IF NOT EXISTS idx_focused_execution_trace_timestamp ON focused_test_case_execution_trace_entries(timestamp);
    CREATE INDEX IF NOT EXISTS idx_focused_reasoning_trace_scan_id ON focused_reasoning_trace_entries(scan_id);
    CREATE INDEX IF NOT EXISTS idx_focused_reasoning_trace_case_id ON focused_reasoning_trace_entries(case_id);
    CREATE INDEX IF NOT EXISTS idx_focused_reasoning_trace_execution_id ON focused_reasoning_trace_entries(execution_id);
    CREATE INDEX IF NOT EXISTS idx_focused_reasoning_trace_stage ON focused_reasoning_trace_entries(stage);
    CREATE INDEX IF NOT EXISTS idx_focused_reasoning_trace_timestamp ON focused_reasoning_trace_entries(timestamp);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_evidence_scan_id ON focused_test_case_evidence_bundles(scan_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_evidence_case_id ON focused_test_case_evidence_bundles(case_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_evidence_execution_id ON focused_test_case_evidence_bundles(execution_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_evidence_captured_at ON focused_test_case_evidence_bundles(captured_at);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_verdicts_scan_id ON focused_test_case_verdicts(scan_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_verdicts_case_id ON focused_test_case_verdicts(case_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_verdicts_execution_id ON focused_test_case_verdicts(execution_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_verdicts_verdict_at ON focused_test_case_verdicts(verdict_at);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_findings_scan_id ON focused_test_case_findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_findings_case_id ON focused_test_case_findings(case_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_findings_execution_id ON focused_test_case_findings(execution_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_findings_status ON focused_test_case_findings(status);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_findings_primary ON focused_test_case_findings(scan_id, is_primary, rank_order);
    CREATE INDEX IF NOT EXISTS idx_focused_scan_verdict_summaries_objective_id ON focused_scan_verdict_summaries(objective_id);
    CREATE INDEX IF NOT EXISTS idx_focused_investigation_issues_scan_id ON focused_test_case_investigation_issues(scan_id);
    CREATE INDEX IF NOT EXISTS idx_focused_investigation_issues_case_id ON focused_test_case_investigation_issues(case_id);
    CREATE INDEX IF NOT EXISTS idx_focused_investigation_issues_execution_id ON focused_test_case_investigation_issues(execution_id);
    CREATE INDEX IF NOT EXISTS idx_focused_investigation_issues_issue_type ON focused_test_case_investigation_issues(issue_type);
    CREATE INDEX IF NOT EXISTS idx_focused_investigation_issues_issue_status ON focused_test_case_investigation_issues(issue_status);
    CREATE INDEX IF NOT EXISTS idx_focused_investigation_issues_impact ON focused_test_case_investigation_issues(impact);
    CREATE INDEX IF NOT EXISTS idx_focused_scan_blocker_summaries_objective_id ON focused_scan_blocker_summaries(objective_id);
    CREATE INDEX IF NOT EXISTS idx_focused_scan_historical_compare_states_scope_identity ON focused_scan_historical_compare_states(scope_identity_key);
    CREATE INDEX IF NOT EXISTS idx_focused_scan_historical_compare_states_baseline_scan_id ON focused_scan_historical_compare_states(baseline_scan_id);
    CREATE INDEX IF NOT EXISTS idx_focused_scan_historical_compare_states_compared_against_scan_id ON focused_scan_historical_compare_states(compared_against_scan_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_historical_compares_current_scan_case ON focused_test_case_historical_compares(current_scan_id, current_case_id);
    CREATE INDEX IF NOT EXISTS idx_focused_test_case_historical_compares_previous_scan_case ON focused_test_case_historical_compares(previous_scan_id, previous_case_id);
    CREATE INDEX IF NOT EXISTS idx_focused_scan_historical_compare_summaries_compared_against_scan_id ON focused_scan_historical_compare_summaries(compared_against_scan_id);

    -- Report analyses (Red Team Mind Reconstruction)
    CREATE TABLE IF NOT EXISTS report_analyses (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      file_path TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','parsing','analyzing','completed','failed')),
      report_metadata_json TEXT,
      behavioral_profile_json TEXT,
      defensive_intel_json TEXT,
      error_message TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- Analysis findings (one per extracted vulnerability)
    CREATE TABLE IF NOT EXISTS analysis_findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      analysis_id TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT,
      cvss_score REAL,
      cvss_vector TEXT,
      description TEXT,
      poc_steps_json TEXT,
      raw_http_requests_json TEXT,
      payloads_json TEXT,
      evidence_json TEXT,
      recommendation TEXT,
      discovery_method TEXT,
      reasoning_chain_json TEXT,
      skill_estimation TEXT,
      automation_probability REAL,
      defensive_insights_json TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (analysis_id) REFERENCES report_analyses(id) ON DELETE CASCADE
    );

    -- Analysis logs (processing progress)
    CREATE TABLE IF NOT EXISTS analysis_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      analysis_id TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (analysis_id) REFERENCES report_analyses(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_report_analyses_user_id ON report_analyses(user_id);
    CREATE INDEX IF NOT EXISTS idx_analysis_findings_analysis_id ON analysis_findings(analysis_id);
    CREATE INDEX IF NOT EXISTS idx_analysis_logs_analysis_id ON analysis_logs(analysis_id);

    -- Mindset TTP library (learned tactics from reports)
    CREATE TABLE IF NOT EXISTS mindset_ttps (
      id TEXT PRIMARY KEY,
      source_analysis_id TEXT NOT NULL,
      source_finding_id INTEGER,
      title TEXT NOT NULL,
      vulnerability_class TEXT NOT NULL,
      discovery_strategy_json TEXT,
      preconditions_json TEXT,
      entrypoint_hints_json TEXT,
      request_templates_json TEXT,
      payload_templates_json TEXT,
      verification_criteria_json TEXT,
      confidence REAL DEFAULT 0.5,
      generalization_notes TEXT,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (source_analysis_id) REFERENCES report_analyses(id) ON DELETE CASCADE
    );

    -- Aggregated mindset profile
    CREATE TABLE IF NOT EXISTS mindset_profile (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      profile_json TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_mindset_ttps_analysis ON mindset_ttps(source_analysis_id);
    CREATE INDEX IF NOT EXISTS idx_mindset_ttps_class ON mindset_ttps(vulnerability_class);

    -- TTP Test Playbook cache (AI-generated testing guides)
    CREATE TABLE IF NOT EXISTS ttp_test_playbooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ttp_id TEXT NOT NULL,
      content TEXT NOT NULL,
      model TEXT,
      tokens INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (ttp_id) REFERENCES mindset_ttps(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_ttp_playbooks_ttp ON ttp_test_playbooks(ttp_id);

    -- Presence Scan Runs
    CREATE TABLE IF NOT EXISTS presence_scan_runs (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      ttp_id TEXT NOT NULL,
      ttp_title TEXT,
      status TEXT DEFAULT 'pending',
      targets_count INTEGER DEFAULT 0,
      results_present INTEGER DEFAULT 0,
      results_likely INTEGER DEFAULT 0,
      results_absent INTEGER DEFAULT 0,
      results_unknown INTEGER DEFAULT 0,
      started_at DATETIME,
      finished_at DATETIME,
      error_message TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    -- Per-target results for each run
    CREATE TABLE IF NOT EXISTS presence_scan_targets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      target_raw TEXT NOT NULL,
      target_url TEXT NOT NULL,
      target_host TEXT,
      target_port INTEGER,
      target_scheme TEXT,
      status TEXT DEFAULT 'pending',
      verdict TEXT,
      verdict_reason TEXT,
      evidence_json TEXT,
      request_sent TEXT,
      response_excerpt TEXT,
      checked_at DATETIME,
      FOREIGN KEY (run_id) REFERENCES presence_scan_runs(id) ON DELETE CASCADE
    );

    -- Audit log per run
    CREATE TABLE IF NOT EXISTS presence_scan_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (run_id) REFERENCES presence_scan_runs(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_psr_user ON presence_scan_runs(user_id);
    CREATE INDEX IF NOT EXISTS idx_psr_ttp ON presence_scan_runs(ttp_id);
    CREATE INDEX IF NOT EXISTS idx_pst_run ON presence_scan_targets(run_id);
    CREATE INDEX IF NOT EXISTS idx_pst_verdict ON presence_scan_targets(verdict);
    CREATE INDEX IF NOT EXISTS idx_psl_run ON presence_scan_logs(run_id);

    -- Join table: multiple TTPs per presence scan run
    CREATE TABLE IF NOT EXISTS presence_scan_run_ttps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      ttp_id TEXT NOT NULL,
      ttp_title TEXT,
      FOREIGN KEY (run_id) REFERENCES presence_scan_runs(id) ON DELETE CASCADE,
      UNIQUE(run_id, ttp_id)
    );

    CREATE INDEX IF NOT EXISTS idx_psrt_run ON presence_scan_run_ttps(run_id);
    CREATE INDEX IF NOT EXISTS idx_psrt_ttp ON presence_scan_run_ttps(ttp_id);

    -- PenPard Browser sessions
    CREATE TABLE IF NOT EXISTS browser_sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      scan_id TEXT,
      finding_id INTEGER,
      target_url TEXT,
      status TEXT DEFAULT 'launching' CHECK(status IN ('launching','active','paused','closed')),
      lifecycle_state TEXT DEFAULT 'launching',
      lifecycle_detail TEXT,
      last_error TEXT,
      mode TEXT DEFAULT 'human' CHECK(mode IN ('human','ai','mixed')),
      current_url TEXT,
      proxy_host TEXT,
      proxy_port INTEGER,
      launched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      closed_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
    );

    -- PenPard Browser action/event log (for future replay/PoC)
    CREATE TABLE IF NOT EXISTS browser_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      action_type TEXT NOT NULL,
      action_data TEXT,
      page_url TEXT,
      page_title TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      source TEXT DEFAULT 'human' CHECK(source IN ('human','ai','system')),
      FOREIGN KEY (session_id) REFERENCES browser_sessions(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_browser_sessions_user ON browser_sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_browser_sessions_status ON browser_sessions(status);
    CREATE INDEX IF NOT EXISTS idx_browser_sessions_scan ON browser_sessions(scan_id);
    CREATE INDEX IF NOT EXISTS idx_browser_actions_session ON browser_actions(session_id);

    -- User integrations (OAuth tokens for external services like GitHub)
    CREATE TABLE IF NOT EXISTS user_integrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL DEFAULT 1,
      provider TEXT NOT NULL,
      access_token_encrypted TEXT,
      token_iv TEXT,
      refresh_token_encrypted TEXT,
      refresh_token_iv TEXT,
      token_scope TEXT,
      external_username TEXT,
      external_avatar_url TEXT,
      connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      is_active INTEGER NOT NULL DEFAULT 1,
      metadata_json TEXT DEFAULT '{}',
      UNIQUE(user_id, provider),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_user_integrations_user ON user_integrations(user_id);
    CREATE INDEX IF NOT EXISTS idx_user_integrations_provider ON user_integrations(provider);

    -- Short-lived OAuth authorization sessions for browser callbacks
    CREATE TABLE IF NOT EXISTS integration_auth_sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      provider TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending', 'completed', 'failed', 'expired')),
      state TEXT NOT NULL UNIQUE,
      code_verifier TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      app_redirect_url TEXT,
      authorization_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      completed_at DATETIME,
      error_message TEXT,
      result_json TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_integration_auth_sessions_user ON integration_auth_sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_integration_auth_sessions_provider_status ON integration_auth_sessions(provider, status);
  `);

  // Seed lock_key_hash if not exists (default key: "penpard")
  const lockKeyHash = bcrypt.hashSync('penpard', 12);
  db.prepare(`INSERT OR IGNORE INTO settings (key, value) VALUES ('lock_key_hash', ?)`).run(lockKeyHash);

  // Seed operator user if not exists (for scans - user_id reference)
  const operatorExists = db.prepare('SELECT id FROM users WHERE username = ?').get('operator');
  const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');

  if (!operatorExists) {
    if (adminExists) {
      // Migrate existing admin to operator (keep id=1 for existing scans/whitelists)
      const passwordHash = bcrypt.hashSync('operator', 12);
      db.prepare(`
        UPDATE users SET username = 'operator', password_hash = ?, role = 'super_admin', credits = 999999, updated_at = CURRENT_TIMESTAMP
        WHERE username = 'admin'
      `).run(passwordHash);
      logger.info('Migrated admin user to operator (999999 credits)');
    } else {
      const passwordHash = bcrypt.hashSync('operator', 12);
      db.prepare(`
        INSERT INTO users (username, password_hash, role, credits)
        VALUES (?, ?, 'super_admin', 999999)
      `).run('operator', passwordHash);
      logger.info('Created default operator user (999999 credits)');
    }
  }

  // Migration: scans.initial_request (Send to PenPard raw request for continue-scan)
  const scanCols = db.prepare('PRAGMA table_info(scans)').all() as { name: string }[];
  if (!scanCols.some((c) => c.name === 'scan_mode')) {
    db.exec(`ALTER TABLE scans ADD COLUMN scan_mode TEXT NOT NULL DEFAULT 'exploratory'`);
    logger.info('Added scans.scan_mode column');
  }
  if (!scanCols.some((c) => c.name === 'initial_request')) {
    db.exec('ALTER TABLE scans ADD COLUMN initial_request TEXT');
    logger.info('Added scans.initial_request column');
  }

  // Migration: source analysis columns
  if (!scanCols.some((c) => c.name === 'source_package_path')) {
    db.exec('ALTER TABLE scans ADD COLUMN source_package_path TEXT');
    logger.info('Added scans.source_package_path column');
  }
  if (!scanCols.some((c) => c.name === 'source_analysis_mode')) {
    db.exec('ALTER TABLE scans ADD COLUMN source_analysis_mode TEXT');
    logger.info('Added scans.source_analysis_mode column');
  }
  if (!scanCols.some((c) => c.name === 'source_analysis_result_json')) {
    db.exec('ALTER TABLE scans ADD COLUMN source_analysis_result_json TEXT');
    logger.info('Added scans.source_analysis_result_json column');
  }
  if (!scanCols.some((c) => c.name === 'scan_config_json')) {
    db.exec('ALTER TABLE scans ADD COLUMN scan_config_json TEXT');
    logger.info('Added scans.scan_config_json column');
  }
  if (!scanCols.some((c) => c.name === 'auth_inventory_json')) {
    db.exec('ALTER TABLE scans ADD COLUMN auth_inventory_json TEXT');
    logger.info('Added scans.auth_inventory_json column');
  }
if (!scanCols.some((c) => c.name === 'endpoint_inventory_json')) {
  db.exec('ALTER TABLE scans ADD COLUMN endpoint_inventory_json TEXT');
  logger.info('Added scans.endpoint_inventory_json column');
}
if (!scanCols.some((c) => c.name === 'runtime_checkpoint_json')) {
  db.exec('ALTER TABLE scans ADD COLUMN runtime_checkpoint_json TEXT');
  logger.info('Added scans.runtime_checkpoint_json column');
}

  const tokenUsageCols = db.prepare('PRAGMA table_info(token_usage)').all() as { name: string }[];
  if (!tokenUsageCols.some((c) => c.name === 'report_export_id')) {
    db.exec('ALTER TABLE token_usage ADD COLUMN report_export_id TEXT');
    logger.info('Added token_usage.report_export_id column');
  }
  if (!tokenUsageCols.some((c) => c.name === 'reasoning_tokens')) {
    db.exec('ALTER TABLE token_usage ADD COLUMN reasoning_tokens INTEGER NOT NULL DEFAULT 0');
    logger.info('Added token_usage.reasoning_tokens column');
  }
  db.exec('CREATE INDEX IF NOT EXISTS idx_token_usage_report_export_id ON token_usage(report_export_id)');

  // Migration: browser_sessions.label (user-friendly session names for multi-session testing)
  const browserCols = db.prepare('PRAGMA table_info(browser_sessions)').all() as { name: string }[];
  if (!browserCols.some((c) => c.name === 'label')) {
    db.exec('ALTER TABLE browser_sessions ADD COLUMN label TEXT');
    logger.info('Added browser_sessions.label column');
  }
  if (!browserCols.some((c) => c.name === 'lifecycle_state')) {
    db.exec(`ALTER TABLE browser_sessions ADD COLUMN lifecycle_state TEXT DEFAULT 'launching'`);
    logger.info('Added browser_sessions.lifecycle_state column');
  }
  if (!browserCols.some((c) => c.name === 'lifecycle_detail')) {
    db.exec('ALTER TABLE browser_sessions ADD COLUMN lifecycle_detail TEXT');
    logger.info('Added browser_sessions.lifecycle_detail column');
  }
  if (!browserCols.some((c) => c.name === 'last_error')) {
    db.exec('ALTER TABLE browser_sessions ADD COLUMN last_error TEXT');
    logger.info('Added browser_sessions.last_error column');
  }

  const focusedExecutionCols = db.prepare('PRAGMA table_info(focused_test_case_executions)').all() as { name: string }[];
  if (!focusedExecutionCols.some((c) => c.name === 'browser_actions_used')) {
    db.exec('ALTER TABLE focused_test_case_executions ADD COLUMN browser_actions_used INTEGER NOT NULL DEFAULT 0');
    logger.info('Added focused_test_case_executions.browser_actions_used column');
  }
  if (!focusedExecutionCols.some((c) => c.name === 'browser_session_id')) {
    db.exec('ALTER TABLE focused_test_case_executions ADD COLUMN browser_session_id TEXT');
    logger.info('Added focused_test_case_executions.browser_session_id column');
  }

  const focusedEvidenceCols = db.prepare('PRAGMA table_info(focused_test_case_evidence_bundles)').all() as { name: string }[];
  if (!focusedEvidenceCols.some((c) => c.name === 'browser_state_json')) {
    db.exec('ALTER TABLE focused_test_case_evidence_bundles ADD COLUMN browser_state_json TEXT');
    logger.info('Added focused_test_case_evidence_bundles.browser_state_json column');
  }
  if (!focusedEvidenceCols.some((c) => c.name === 'related_evidence_ids_json')) {
    db.exec('ALTER TABLE focused_test_case_evidence_bundles ADD COLUMN related_evidence_ids_json TEXT');
    logger.info('Added focused_test_case_evidence_bundles.related_evidence_ids_json column');
  }

  const focusedVerdictCols = db.prepare('PRAGMA table_info(focused_test_case_verdicts)').all() as { name: string }[];
  if (!focusedVerdictCols.some((c) => c.name === 'interpretation_summary_json')) {
    db.exec('ALTER TABLE focused_test_case_verdicts ADD COLUMN interpretation_summary_json TEXT');
    logger.info('Added focused_test_case_verdicts.interpretation_summary_json column');
  }
  if (!focusedVerdictCols.some((c) => c.name === 'support_provenance_json')) {
    db.exec('ALTER TABLE focused_test_case_verdicts ADD COLUMN support_provenance_json TEXT');
    logger.info('Added focused_test_case_verdicts.support_provenance_json column');
  }
  if (!focusedVerdictCols.some((c) => c.name === 'request_evidence_story_json')) {
    db.exec('ALTER TABLE focused_test_case_verdicts ADD COLUMN request_evidence_story_json TEXT');
    logger.info('Added focused_test_case_verdicts.request_evidence_story_json column');
  }

  const focusedFindingCols = db.prepare('PRAGMA table_info(focused_test_case_findings)').all() as { name: string }[];
  if (!focusedFindingCols.some((c) => c.name === 'support_provenance_json')) {
    db.exec('ALTER TABLE focused_test_case_findings ADD COLUMN support_provenance_json TEXT');
    logger.info('Added focused_test_case_findings.support_provenance_json column');
  }
  if (!focusedFindingCols.some((c) => c.name === 'request_evidence_story_json')) {
    db.exec('ALTER TABLE focused_test_case_findings ADD COLUMN request_evidence_story_json TEXT');
    logger.info('Added focused_test_case_findings.request_evidence_story_json column');
  }

  const focusedFindingThreadCols = db.prepare('PRAGMA table_info(focused_test_case_finding_threads)').all() as { name: string }[];
  if (!focusedFindingThreadCols.some((c) => c.name === 'support_provenance_json')) {
    db.exec('ALTER TABLE focused_test_case_finding_threads ADD COLUMN support_provenance_json TEXT');
    logger.info('Added focused_test_case_finding_threads.support_provenance_json column');
  }
  if (!focusedFindingThreadCols.some((c) => c.name === 'request_evidence_story_json')) {
    db.exec('ALTER TABLE focused_test_case_finding_threads ADD COLUMN request_evidence_story_json TEXT');
    logger.info('Added focused_test_case_finding_threads.request_evidence_story_json column');
  }

  const focusedCaseCols = db.prepare('PRAGMA table_info(focused_test_cases)').all() as { name: string }[];
  if (!focusedCaseCols.some((c) => c.name === 'case_family')) {
    db.exec(`ALTER TABLE focused_test_cases ADD COLUMN case_family TEXT NOT NULL DEFAULT 'generic'`);
    logger.info('Added focused_test_cases.case_family column');
  }
  if (!focusedCaseCols.some((c) => c.name === 'case_intelligence_json')) {
    db.exec(`ALTER TABLE focused_test_cases ADD COLUMN case_intelligence_json TEXT NOT NULL DEFAULT '{}'`);
    logger.info('Added focused_test_cases.case_intelligence_json column');
  }
  if (!focusedCaseCols.some((c) => c.name === 'max_adaptive_follow_ups')) {
    db.exec('ALTER TABLE focused_test_cases ADD COLUMN max_adaptive_follow_ups INTEGER NOT NULL DEFAULT 1');
    logger.info('Added focused_test_cases.max_adaptive_follow_ups column');
  }
  if (!focusedCaseCols.some((c) => c.name === 'preferred_rail')) {
    db.exec(`ALTER TABLE focused_test_cases ADD COLUMN preferred_rail TEXT NOT NULL DEFAULT 'request'`);
    logger.info('Added focused_test_cases.preferred_rail column');
  }
  if (!focusedCaseCols.some((c) => c.name === 'allowed_confirmation_kinds_json')) {
    db.exec(`ALTER TABLE focused_test_cases ADD COLUMN allowed_confirmation_kinds_json TEXT NOT NULL DEFAULT '[]'`);
    logger.info('Added focused_test_cases.allowed_confirmation_kinds_json column');
  }

  const integrationCols = db.prepare('PRAGMA table_info(user_integrations)').all() as { name: string }[];
  if (!integrationCols.some((c) => c.name === 'refresh_token_encrypted')) {
    db.exec('ALTER TABLE user_integrations ADD COLUMN refresh_token_encrypted TEXT');
    logger.info('Added user_integrations.refresh_token_encrypted column');
  }
  if (!integrationCols.some((c) => c.name === 'refresh_token_iv')) {
    db.exec('ALTER TABLE user_integrations ADD COLUMN refresh_token_iv TEXT');
    logger.info('Added user_integrations.refresh_token_iv column');
  }

  const scopeEnvelopeCols = db.prepare('PRAGMA table_info(scope_envelopes)').all() as { name: string }[];
  if (!scopeEnvelopeCols.some((c) => c.name === 'discovered_request_refs_json')) {
    db.exec('ALTER TABLE scope_envelopes ADD COLUMN discovered_request_refs_json TEXT');
    logger.info('Added scope_envelopes.discovered_request_refs_json column');
  }
  if (!scopeEnvelopeCols.some((c) => c.name === 'browser_anchors_json')) {
    db.exec('ALTER TABLE scope_envelopes ADD COLUMN browser_anchors_json TEXT');
    logger.info('Added scope_envelopes.browser_anchors_json column');
  }

  logger.info('Database initialized successfully');
}

// Helper functions
export const findUserById = (id: number) => {
  return db.prepare('SELECT id, username, role, credits, created_at FROM users WHERE id = ?').get(id) as any;
};

export const updateUserCredits = (userId: number, credits: number) => {
  return db.prepare('UPDATE users SET credits = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(credits, userId);
};

export const getUserWhitelists = (userId: number) => {
  return db.prepare('SELECT * FROM whitelists WHERE user_id = ?').all(userId) as any[];
};

function parseJsonColumn<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

export const createScan = (data: {
  id: string; userId: number; type: string; target: string;
  scanMode?: ScanMode;
  sourcePackagePath?: string; sourceAnalysisMode?: string;
}) => {
  return db.prepare(`
    INSERT INTO scans (id, user_id, type, scan_mode, target, status, source_package_path, source_analysis_mode)
    VALUES (?, ?, ?, ?, ?, 'queued', ?, ?)
  `).run(
    data.id,
    data.userId,
    data.type,
    data.scanMode ?? 'exploratory',
    data.target,
    data.sourcePackagePath ?? null,
    data.sourceAnalysisMode ?? null,
  );
};

export const getScan = (id: string) => {
  return db.prepare('SELECT * FROM scans WHERE id = ?').get(id) as any;
};

export const updateScanStatus = (id: string, status: string, errorMessage?: string) => {
  if (status === 'completed' || status === 'failed' || status === 'stopped' || status === 'interrupted' || status === 'scoped_executed') {
    return db.prepare(`
      UPDATE scans SET status = ?, completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP), error_message = ?
      WHERE id = ?
    `).run(status, errorMessage || null, id);
  }
  if (errorMessage !== undefined) {
    return db.prepare(`
      UPDATE scans SET status = ?, error_message = ?, completed_at = NULL
      WHERE id = ?
    `).run(status, errorMessage || null, id);
  }
  return db.prepare('UPDATE scans SET status = ? WHERE id = ?').run(status, id);
};

export const setScanInitialRequest = (scanId: string, rawRequest: string | null) => {
  return db.prepare('UPDATE scans SET initial_request = ? WHERE id = ?').run(rawRequest ?? null, scanId);
};

export const saveSourceAnalysisResult = (scanId: string, resultJson: string) => {
  return db.prepare('UPDATE scans SET source_analysis_result_json = ? WHERE id = ?').run(resultJson, scanId);
};

export const saveScanConfig = (scanId: string, configJson: string) => {
  return db.prepare('UPDATE scans SET scan_config_json = ? WHERE id = ?').run(configJson, scanId);
};

export const getScanConfig = (scanId: string): Record<string, any> | null => {
  const row = db.prepare('SELECT scan_config_json FROM scans WHERE id = ?').get(scanId) as any;
  return parseJsonColumn<Record<string, any> | null>(row?.scan_config_json, null);
};

export const saveScanAuthInventory = (scanId: string, inventoryJson: string) => {
  return db.prepare('UPDATE scans SET auth_inventory_json = ? WHERE id = ?').run(inventoryJson, scanId);
};

export const getScanAuthInventory = (scanId: string): any | null => {
  const row = db.prepare('SELECT auth_inventory_json FROM scans WHERE id = ?').get(scanId) as any;
  return parseJsonColumn<any | null>(row?.auth_inventory_json, null);
};

export const saveScanEndpointInventory = (scanId: string, inventoryJson: string) => {
  return db.prepare('UPDATE scans SET endpoint_inventory_json = ? WHERE id = ?').run(inventoryJson, scanId);
};

export const getScanEndpointInventory = (scanId: string): any | null => {
  const row = db.prepare('SELECT endpoint_inventory_json FROM scans WHERE id = ?').get(scanId) as any;
  if (!row?.endpoint_inventory_json) return null;
  try { return JSON.parse(row.endpoint_inventory_json); } catch { return null; }
};

export const saveScanRuntimeCheckpoint = (scanId: string, checkpointJson: string) => {
  return db.prepare('UPDATE scans SET runtime_checkpoint_json = ? WHERE id = ?').run(checkpointJson, scanId);
};

export const getScanRuntimeCheckpoint = (scanId: string): any | null => {
  const row = db.prepare('SELECT runtime_checkpoint_json FROM scans WHERE id = ?').get(scanId) as any;
  if (!row?.runtime_checkpoint_json) return null;
  try { return JSON.parse(row.runtime_checkpoint_json); } catch { return null; }
};

export const getSourceAnalysisResult = (scanId: string): any | null => {
  const row = db.prepare('SELECT source_analysis_result_json FROM scans WHERE id = ?').get(scanId) as any;
  if (!row?.source_analysis_result_json) return null;
  try { return JSON.parse(row.source_analysis_result_json); } catch { return null; }
};

export const createFocusedTestObjective = (objective: FocusedTestObjective) => {
  return db.prepare(`
    INSERT INTO focused_test_objectives (
      id, scan_id, title, scope_type, feature_description, goal, operator_notes, risk_tags_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    objective.id,
    objective.scanId,
    objective.title,
    objective.scopeType,
    objective.featureDescription ?? null,
    objective.goal ?? null,
    objective.operatorNotes ?? null,
    JSON.stringify(objective.riskTags || []),
  );
};

export const getFocusedTestObjective = (scanId: string): FocusedTestObjective | null => {
  const row = db.prepare('SELECT * FROM focused_test_objectives WHERE scan_id = ?').get(scanId) as any;
  if (!row) return null;

  return {
    id: row.id,
    scanId: row.scan_id,
    title: row.title,
    scopeType: row.scope_type,
    featureDescription: row.feature_description ?? undefined,
    goal: row.goal ?? undefined,
    operatorNotes: row.operator_notes ?? undefined,
    riskTags: parseJsonColumn<string[]>(row.risk_tags_json, []),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
};

export const updateFocusedTestObjective = (scanId: string, updates: {
  title?: string;
  scopeType?: string;
  featureDescription?: string | null;
  goal?: string | null;
  operatorNotes?: string | null;
  riskTags?: string[];
}) => {
  const assignments: string[] = [];
  const values: any[] = [];

  if (updates.title !== undefined) {
    assignments.push('title = ?');
    values.push(updates.title);
  }
  if (updates.scopeType !== undefined) {
    assignments.push('scope_type = ?');
    values.push(updates.scopeType);
  }
  if (updates.featureDescription !== undefined) {
    assignments.push('feature_description = ?');
    values.push(updates.featureDescription ?? null);
  }
  if (updates.goal !== undefined) {
    assignments.push('goal = ?');
    values.push(updates.goal ?? null);
  }
  if (updates.operatorNotes !== undefined) {
    assignments.push('operator_notes = ?');
    values.push(updates.operatorNotes ?? null);
  }
  if (updates.riskTags !== undefined) {
    assignments.push('risk_tags_json = ?');
    values.push(JSON.stringify(updates.riskTags || []));
  }

  if (assignments.length === 0) {
    return getFocusedTestObjective(scanId);
  }

  assignments.push('updated_at = CURRENT_TIMESTAMP');
  values.push(scanId);

  db.prepare(`
    UPDATE focused_test_objectives
    SET ${assignments.join(', ')}
    WHERE scan_id = ?
  `).run(...values);

  return getFocusedTestObjective(scanId);
};

export const createScopedTestRequest = (request: StructuredSecurityTestRequest & { id: string; scanId: string }) => {
  return db.prepare(`
    INSERT INTO scoped_test_requests (
      id,
      scan_id,
      target_url,
      description,
      environment,
      service_name,
      test_data_json,
      test_users_json,
      login_present,
      auth_mechanism_hints_json,
      has_screenshot_or_attachment,
      attachment_metadata_json,
      attachment_summary,
      new_screen_count,
      new_input_count,
      operator_notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    request.id,
    request.scanId,
    request.targetUrl,
    request.description,
    request.environment ?? null,
    request.serviceName ?? null,
    JSON.stringify(request.testData || []),
    JSON.stringify(request.testUsers || []),
    request.loginPresent === undefined || request.loginPresent === null ? null : (request.loginPresent ? 1 : 0),
    JSON.stringify(request.authMechanismHints || []),
    request.hasScreenshotOrAttachment === undefined || request.hasScreenshotOrAttachment === null ? null : (request.hasScreenshotOrAttachment ? 1 : 0),
    JSON.stringify(request.attachmentMetadata || []),
    request.attachmentSummary ?? null,
    request.newScreenCount ?? null,
    request.newInputCount ?? null,
    request.operatorNotes ?? null,
  );
};

export const getScopedTestRequest = (scanId: string): StructuredSecurityTestRequest | null => {
  const row = db.prepare('SELECT * FROM scoped_test_requests WHERE scan_id = ?').get(scanId) as any;
  if (!row) return null;

  return {
    scanId: row.scan_id,
    targetUrl: row.target_url,
    description: row.description,
    environment: row.environment ?? undefined,
    serviceName: row.service_name ?? undefined,
    testData: parseJsonColumn<string[]>(row.test_data_json, []),
    testUsers: parseJsonColumn<string[]>(row.test_users_json, []),
    loginPresent: row.login_present === null || row.login_present === undefined
      ? null
      : Number(row.login_present) > 0,
    authMechanismHints: parseJsonColumn<string[]>(row.auth_mechanism_hints_json, []),
    hasScreenshotOrAttachment: row.has_screenshot_or_attachment === null || row.has_screenshot_or_attachment === undefined
      ? null
      : Number(row.has_screenshot_or_attachment) > 0,
    attachmentMetadata: parseJsonColumn<any[]>(row.attachment_metadata_json, []),
    attachmentSummary: row.attachment_summary ?? undefined,
    newScreenCount: row.new_screen_count === null || row.new_screen_count === undefined
      ? null
      : Number(row.new_screen_count),
    newInputCount: row.new_input_count === null || row.new_input_count === undefined
      ? null
      : Number(row.new_input_count),
    operatorNotes: row.operator_notes ?? undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
};

export const createScopedFeatureDiscoveryState = (state: ScopedFeatureDiscoveryState) => {
  return db.prepare(`
    INSERT INTO scoped_feature_discovery_states (
      id,
      scan_id,
      phase,
      outcome,
      summary,
      error_message,
      request_anchor_count,
      browser_anchor_count,
      selected_endpoint_count,
      allowed_route_count,
      started_at,
      completed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    state.id,
    state.scanId,
    state.phase,
    state.outcome ?? null,
    state.summary ?? null,
    state.errorMessage ?? null,
    state.requestAnchorCount,
    state.browserAnchorCount,
    state.selectedEndpointCount,
    state.allowedRouteCount,
    state.startedAt ?? null,
    state.completedAt ?? null,
  );
};

export const getScopedFeatureDiscoveryState = (scanId: string): ScopedFeatureDiscoveryState | null => {
  const row = db.prepare('SELECT * FROM scoped_feature_discovery_states WHERE scan_id = ?').get(scanId) as any;
  if (!row) return null;

  return {
    id: row.id,
    scanId: row.scan_id,
    phase: normalizeScopedFeatureDiscoveryPhase(row.phase),
    outcome: normalizeScopedFeatureDiscoveryOutcome(row.outcome),
    summary: row.summary ?? null,
    errorMessage: row.error_message ?? null,
    requestAnchorCount: Number(row.request_anchor_count) || 0,
    browserAnchorCount: Number(row.browser_anchor_count) || 0,
    selectedEndpointCount: Number(row.selected_endpoint_count) || 0,
    allowedRouteCount: Number(row.allowed_route_count) || 0,
    startedAt: row.started_at ?? null,
    completedAt: row.completed_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
};

export const updateScopedFeatureDiscoveryState = (scanId: string, updates: Partial<Omit<ScopedFeatureDiscoveryState, 'id' | 'scanId' | 'createdAt' | 'updatedAt'>>) => {
  const assignments: string[] = [];
  const values: any[] = [];

  if (updates.phase !== undefined) {
    assignments.push('phase = ?');
    values.push(updates.phase);
  }
  if (updates.outcome !== undefined) {
    assignments.push('outcome = ?');
    values.push(updates.outcome ?? null);
  }
  if (updates.summary !== undefined) {
    assignments.push('summary = ?');
    values.push(updates.summary ?? null);
  }
  if (updates.errorMessage !== undefined) {
    assignments.push('error_message = ?');
    values.push(updates.errorMessage ?? null);
  }
  if (updates.requestAnchorCount !== undefined) {
    assignments.push('request_anchor_count = ?');
    values.push(updates.requestAnchorCount);
  }
  if (updates.browserAnchorCount !== undefined) {
    assignments.push('browser_anchor_count = ?');
    values.push(updates.browserAnchorCount);
  }
  if (updates.selectedEndpointCount !== undefined) {
    assignments.push('selected_endpoint_count = ?');
    values.push(updates.selectedEndpointCount);
  }
  if (updates.allowedRouteCount !== undefined) {
    assignments.push('allowed_route_count = ?');
    values.push(updates.allowedRouteCount);
  }
  if (updates.startedAt !== undefined) {
    assignments.push('started_at = ?');
    values.push(updates.startedAt ?? null);
  }
  if (updates.completedAt !== undefined) {
    assignments.push('completed_at = ?');
    values.push(updates.completedAt ?? null);
  }

  if (assignments.length === 0) {
    return getScopedFeatureDiscoveryState(scanId);
  }

  assignments.push('updated_at = CURRENT_TIMESTAMP');
  values.push(scanId);

  db.prepare(`
    UPDATE scoped_feature_discovery_states
    SET ${assignments.join(', ')}
    WHERE scan_id = ?
  `).run(...values);

  return getScopedFeatureDiscoveryState(scanId);
};

export const createScopeEnvelope = (envelope: ScopeEnvelope) => {
  return db.prepare(`
    INSERT INTO scope_envelopes (
      id,
      scan_id,
      version,
      allowed_hosts_json,
      allowed_routes_json,
      selected_endpoints_json,
      baseline_request_refs_json,
      discovered_request_refs_json,
      browser_anchors_json,
      request_bundle_refs_json,
      auth_context_json,
      out_of_scope_notes_json,
      boundary_hints_json,
      exploration_budget_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    envelope.id,
    envelope.scanId,
    envelope.version,
    JSON.stringify(envelope.allowedHosts || []),
    JSON.stringify(envelope.allowedRoutes || []),
    JSON.stringify(envelope.selectedEndpoints || []),
    JSON.stringify(envelope.baselineRequestRefs || []),
    JSON.stringify(envelope.discoveredRequestRefs || []),
    JSON.stringify(envelope.browserAnchors || []),
    JSON.stringify(envelope.requestBundleRefs || []),
    envelope.authContext ? JSON.stringify(envelope.authContext) : null,
    JSON.stringify(envelope.outOfScopeNotes || []),
    JSON.stringify(envelope.boundaryHints || []),
    envelope.explorationBudget ? JSON.stringify(envelope.explorationBudget) : null,
  );
};

export const getScopeEnvelope = (scanId: string): ScopeEnvelope | null => {
  const row = db.prepare('SELECT * FROM scope_envelopes WHERE scan_id = ?').get(scanId) as any;
  if (!row) return null;

  return {
    id: row.id,
    scanId: row.scan_id,
    version: row.version,
    allowedHosts: parseJsonColumn<string[]>(row.allowed_hosts_json, []),
    allowedRoutes: parseJsonColumn<string[]>(row.allowed_routes_json, []),
    selectedEndpoints: parseJsonColumn<any[]>(row.selected_endpoints_json, []),
    baselineRequestRefs: parseJsonColumn<any[]>(row.baseline_request_refs_json, []),
    discoveredRequestRefs: parseJsonColumn<any[]>(row.discovered_request_refs_json, []),
    browserAnchors: parseJsonColumn<any[]>(row.browser_anchors_json, []),
    requestBundleRefs: parseJsonColumn<any[]>(row.request_bundle_refs_json, []),
    authContext: parseJsonColumn<any | null>(row.auth_context_json, null),
    outOfScopeNotes: parseJsonColumn<string[]>(row.out_of_scope_notes_json, []),
    boundaryHints: parseJsonColumn<string[]>(row.boundary_hints_json, []),
    explorationBudget: parseJsonColumn<any | null>(row.exploration_budget_json, null),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
};

export const updateScopeEnvelope = (scanId: string, updates: Partial<Pick<ScopeEnvelope,
  'allowedHosts'
  | 'allowedRoutes'
  | 'selectedEndpoints'
  | 'baselineRequestRefs'
  | 'discoveredRequestRefs'
  | 'browserAnchors'
  | 'requestBundleRefs'
  | 'authContext'
  | 'outOfScopeNotes'
  | 'boundaryHints'
  | 'explorationBudget'
>>) => {
  const assignments: string[] = [];
  const values: any[] = [];

  if (updates.allowedHosts !== undefined) {
    assignments.push('allowed_hosts_json = ?');
    values.push(JSON.stringify(updates.allowedHosts || []));
  }
  if (updates.allowedRoutes !== undefined) {
    assignments.push('allowed_routes_json = ?');
    values.push(JSON.stringify(updates.allowedRoutes || []));
  }
  if (updates.selectedEndpoints !== undefined) {
    assignments.push('selected_endpoints_json = ?');
    values.push(JSON.stringify(updates.selectedEndpoints || []));
  }
  if (updates.baselineRequestRefs !== undefined) {
    assignments.push('baseline_request_refs_json = ?');
    values.push(JSON.stringify(updates.baselineRequestRefs || []));
  }
  if (updates.discoveredRequestRefs !== undefined) {
    assignments.push('discovered_request_refs_json = ?');
    values.push(JSON.stringify(updates.discoveredRequestRefs || []));
  }
  if (updates.browserAnchors !== undefined) {
    assignments.push('browser_anchors_json = ?');
    values.push(JSON.stringify(updates.browserAnchors || []));
  }
  if (updates.requestBundleRefs !== undefined) {
    assignments.push('request_bundle_refs_json = ?');
    values.push(JSON.stringify(updates.requestBundleRefs || []));
  }
  if (updates.authContext !== undefined) {
    assignments.push('auth_context_json = ?');
    values.push(updates.authContext ? JSON.stringify(updates.authContext) : null);
  }
  if (updates.outOfScopeNotes !== undefined) {
    assignments.push('out_of_scope_notes_json = ?');
    values.push(JSON.stringify(updates.outOfScopeNotes || []));
  }
  if (updates.boundaryHints !== undefined) {
    assignments.push('boundary_hints_json = ?');
    values.push(JSON.stringify(updates.boundaryHints || []));
  }
  if (updates.explorationBudget !== undefined) {
    assignments.push('exploration_budget_json = ?');
    values.push(updates.explorationBudget ? JSON.stringify(updates.explorationBudget) : null);
  }

  if (assignments.length === 0) {
    return getScopeEnvelope(scanId);
  }

  assignments.push('updated_at = CURRENT_TIMESTAMP');
  values.push(scanId);

  db.prepare(`
    UPDATE scope_envelopes
    SET ${assignments.join(', ')}
    WHERE scan_id = ?
  `).run(...values);

  return getScopeEnvelope(scanId);
};

function mapFocusedTestCaseRow(row: any): FocusedTestCase {
  return {
    id: row.id,
    scanId: row.scan_id,
    objectiveId: row.objective_id,
    title: row.title,
    hypothesis: row.hypothesis,
    targetArtifact: parseJsonColumn<any>(row.target_artifact_json, {}),
    preconditions: parseJsonColumn<string[]>(row.preconditions_json, []),
    steps: parseJsonColumn<any[]>(row.steps_json, []),
    assertions: parseJsonColumn<any[]>(row.assertions_json, []),
    requiredEvidence: parseJsonColumn<any[]>(row.required_evidence_json, []),
    priority: row.priority,
    plannerRationaleSummary: row.planner_rationale_summary,
    caseFamily: normalizeFocusedCaseFamily(row.case_family),
    caseIntelligence: normalizeFocusedCaseIntelligence(parseJsonColumn<any>(row.case_intelligence_json, null)),
    maxAdaptiveFollowUps: Number(row.max_adaptive_follow_ups) || 0,
    preferredRail: normalizeFocusedExecutionRail(row.preferred_rail),
    allowedConfirmationKinds: parseJsonColumn<unknown[]>(row.allowed_confirmation_kinds_json, [])
      .map((entry) => normalizeFocusedConfirmationKind(entry)),
    status: row.status,
    reviewState: row.review_state,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapFocusedTestCaseExecutionRow(row: any): FocusedTestCaseExecution {
  return {
    id: row.id,
    scanId: row.scan_id,
    caseId: row.case_id,
    objectiveId: row.objective_id,
    executionState: normalizeFocusedExecutionState(row.execution_state),
    executionProfileKey: row.execution_profile_key,
    runReason: row.run_reason ?? null,
    notesSummary: row.notes_summary ?? null,
    errorMessage: row.error_message ?? null,
    requestActionsUsed: Number(row.request_actions_used) || 0,
    browserActionsUsed: Number(row.browser_actions_used) || 0,
    browserSessionId: row.browser_session_id ?? null,
    startedAt: row.started_at,
    completedAt: row.completed_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapFocusedExecutionTraceEntryRow(row: any): FocusedExecutionTraceEntry {
  return {
    id: row.id,
    scanId: row.scan_id,
    caseId: row.case_id,
    executionId: row.execution_id,
    timestamp: row.timestamp,
    actionType: normalizeFocusedExecutionTraceActionType(row.action_type),
    actionSummary: row.action_summary,
    targetSummary: row.target_summary ?? null,
    requestSummary: parseJsonColumn<any | null>(row.request_summary_json, null),
    responseSummary: parseJsonColumn<any | null>(row.response_summary_json, null),
    reasoningNote: row.reasoning_note ?? null,
    nextStepRationale: row.next_step_rationale ?? null,
    stopReason: row.stop_reason ?? null,
    retryReason: row.retry_reason ?? null,
    rail: normalizeFocusedExecutionRail(row.rail),
    toolSummary: row.tool_summary ?? null,
    linkedEvidenceIds: parseJsonColumn<string[]>(row.linked_evidence_ids_json, []),
    createdAt: row.created_at,
  };
}

function mapFocusedReasoningTraceEntryRow(row: any): FocusedReasoningTraceEntry {
  return {
    id: row.id,
    scanId: row.scan_id,
    objectiveId: row.objective_id,
    caseId: row.case_id ?? null,
    executionId: row.execution_id ?? null,
    timestamp: row.timestamp,
    stage: normalizeFocusedReasoningStage(row.stage),
    entryType: normalizeFocusedReasoningEntryType(row.entry_type),
    rail: normalizeFocusedReasoningRail(row.rail),
    caseFamily: row.case_family ? normalizeFocusedCaseFamily(row.case_family) : null,
    summary: row.summary,
    observationSummary: row.observation_summary ?? null,
    hypothesisRationaleSummary: row.hypothesis_rationale_summary ?? null,
    actionSelectionRationale: row.action_selection_rationale ?? null,
    requestResponseImpactSummary: row.request_response_impact_summary ?? null,
    browserStateImpactSummary: row.browser_state_impact_summary ?? null,
    confidenceShiftSummary: row.confidence_shift_summary ?? null,
    stopRetryBlockRationale: row.stop_retry_block_rationale ?? null,
    linkedEvidenceIds: parseJsonColumn<string[]>(row.linked_evidence_ids_json, []),
    linkedRequestContextKeys: parseJsonColumn<unknown[]>(row.linked_request_context_keys_json, [])
      .map((entry) => normalizeFocusedRequestContextField(entry)),
    contextInfluence: parseJsonColumn<any[]>(row.context_influence_json, []).map((entry) => ({
      field: normalizeFocusedRequestContextField(entry?.field),
      effect: normalizeFocusedReasoningContextEffect(entry?.effect),
      summary: String(entry?.summary || '').trim(),
    })).filter((entry) => entry.summary.length > 0),
    createdAt: row.created_at,
  };
}

function mapEvidenceBundleRow(row: any): EvidenceBundle {
  return {
    id: row.id,
    scanId: row.scan_id,
    caseId: row.case_id,
    executionId: row.execution_id,
    summary: row.summary,
    source: row.source,
    capturedAt: row.captured_at,
    requestRef: parseJsonColumn<any | null>(row.request_ref_json, null),
    responseRef: parseJsonColumn<any | null>(row.response_ref_json, null),
    responseDiffSummary: parseJsonColumn<any | null>(row.response_diff_summary_json, null),
    screenshotRef: parseJsonColumn<any | null>(row.screenshot_ref_json, null),
    browserState: parseJsonColumn<any | null>(row.browser_state_json, null),
    relatedEvidenceIds: parseJsonColumn<string[] | null>(row.related_evidence_ids_json, null) || [],
    executionNotes: row.execution_notes ?? null,
    provenance: parseJsonColumn<any | null>(row.provenance_json, null),
    scopeViolation: parseJsonColumn<any | null>(row.scope_violation_json, null),
    createdAt: row.created_at,
  };
}

function mapFocusedCaseVerdictRow(row: any): FocusedCaseVerdict {
  const evidenceSufficiency = parseJsonColumn<FocusedEvidenceSufficiencyReport>(row.evidence_sufficiency_report_json, {
    state: 'insufficient',
    summary: 'No evidence sufficiency report was persisted.',
    anchoredToTarget: false,
    anchoredMethod: null,
    anchoredPath: null,
    supportingEvidenceIds: [],
    missingRequirements: [],
    unsupportedRequirements: [],
    contradictorySignals: [],
    underminedByScopeViolation: false,
    requirementEvaluations: [],
  });
  const interpretationSummary = parseJsonColumn<FocusedSignalInterpretationSummary>(row.interpretation_summary_json, {
    caseFamily: 'generic',
    suspiciousness: 'none',
    summary: 'No case-aware interpretation summary was persisted.',
    suspiciousSignals: [],
    passSignals: [],
    failSignals: [],
    reviewSignals: [],
    contradictorySignals: [],
    controlSignals: [],
    keywordSignals: [],
    signalMarkers: [],
    parameterHints: [],
    scoreDelta: 0,
    strongestSupport: null,
    strongestBlocker: null,
    missingEvidence: [],
    uncertaintyReasons: [],
    nextStepSummary: null,
    followUpDecisionSummary: null,
    confirmationReadiness: 'not_ready',
    recommendedConfirmationKinds: [],
  });

  return {
    id: row.id,
    scanId: row.scan_id,
    caseId: row.case_id,
    executionId: row.execution_id,
    objectiveId: row.objective_id,
    verdictState: normalizeFocusedVerdictState(row.verdict_state),
    verdictReason: row.verdict_reason,
    evidenceSufficiency: {
      ...evidenceSufficiency,
      state: normalizeFocusedEvidenceSufficiencyState(row.evidence_sufficiency_state || evidenceSufficiency.state),
    },
    interpretationSummary: {
      ...interpretationSummary,
      caseFamily: normalizeFocusedCaseFamily(interpretationSummary.caseFamily),
      suspiciousness: normalizeFocusedSignalSuspiciousness(interpretationSummary.suspiciousness),
      signalMarkers: (interpretationSummary.signalMarkers || []).map((entry) => normalizeFocusedSignalMarker(entry)),
      parameterHints: Array.isArray(interpretationSummary.parameterHints)
        ? interpretationSummary.parameterHints
          .map((entry) => String(entry || '').trim())
          .filter((entry) => entry.length > 0)
        : [],
      scoreDelta: Number(interpretationSummary.scoreDelta) || 0,
      strongestSupport: interpretationSummary.strongestSupport ?? null,
      strongestBlocker: interpretationSummary.strongestBlocker ?? null,
      missingEvidence: Array.isArray(interpretationSummary.missingEvidence)
        ? interpretationSummary.missingEvidence.map((entry) => String(entry || '').trim()).filter(Boolean)
        : [],
      nextStepSummary: interpretationSummary.nextStepSummary ?? null,
      confirmationReadiness: normalizeFocusedConfirmationReadiness(interpretationSummary.confirmationReadiness),
      recommendedConfirmationKinds: Array.isArray(interpretationSummary.recommendedConfirmationKinds)
        ? interpretationSummary.recommendedConfirmationKinds.map((entry) => normalizeFocusedConfirmationKind(entry))
        : [],
    },
    supportingEvidenceRefs: parseJsonColumn<any[]>(row.supporting_evidence_refs_json, []),
    supportProvenance: parseJsonColumn<FocusedSupportProvenanceSummary | null>(row.support_provenance_json, null),
    requestEvidenceStory: parseJsonColumn<FocusedRequestEvidenceStory | null>(row.request_evidence_story_json, null),
    scopeViolationImpact: parseJsonColumn<any>(row.scope_violation_impact_json, {
      hasScopeViolation: false,
      severity: 'none',
      underminesConfidence: false,
      reasons: [],
    }),
    executionSnapshot: parseJsonColumn<any>(row.execution_snapshot_json, {}),
    assistanceProfileKey: row.assistance_profile_key ?? null,
    assistanceProvider: row.assistance_provider ?? null,
    assistanceModel: row.assistance_model ?? null,
    assistanceNarrative: row.assistance_narrative ?? null,
    verdictAt: row.verdict_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapFocusedCaseFindingRow(row: any): FocusedCaseFinding {
  return {
    id: row.id,
    scanId: row.scan_id,
    caseId: row.case_id,
    executionId: row.execution_id,
    objectiveId: row.objective_id,
    findingKey: row.finding_key,
    title: row.title,
    family: normalizeFocusedCaseFamily(row.family),
    status: normalizeFocusedFindingStatus(row.status),
    suspicionScore: Math.max(0, Math.min(100, Number(row.suspicion_score) || 0)),
    confirmationProgress: Math.max(0, Math.min(100, Number(row.confirmation_progress) || 0)),
    confidenceBand: normalizeFocusedFindingConfidenceBand(row.confidence_band),
    rankOrder: Number(row.rank_order) || 0,
    isPrimary: Number(row.is_primary) > 0,
    strongestSupportSummary: row.strongest_support_summary,
    blockingConstraintSummary: row.blocking_constraint_summary ?? null,
    nextStepSummary: row.next_step_summary ?? null,
    supportingSignals: parseJsonColumn<string[]>(row.supporting_signals_json, []),
    blockingConstraints: parseJsonColumn<string[]>(row.blocking_constraints_json, []),
    supportingEvidenceRefs: parseJsonColumn<any[]>(row.supporting_evidence_refs_json, []),
    supportProvenance: parseJsonColumn<FocusedSupportProvenanceSummary | null>(row.support_provenance_json, null),
    requestEvidenceStory: parseJsonColumn<FocusedRequestEvidenceStory | null>(row.request_evidence_story_json, null),
    linkedVerdictIds: parseJsonColumn<string[]>(row.linked_verdict_ids_json, []),
    linkedInvestigationIds: parseJsonColumn<string[]>(row.linked_investigation_ids_json, []),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function buildEmptyFocusedConfirmationState(): FocusedConfirmationState {
  return {
    maxAdaptiveFollowUps: 0,
    usedAdaptiveFollowUps: 0,
    preferredRail: 'request',
    allowedConfirmationKinds: [],
    recommendedConfirmationKinds: [],
    nextKind: null,
    nextStepSummary: null,
    readyForAdaptiveConfirmation: false,
    exhausted: false,
    stopReason: null,
    steps: [],
  };
}

function mapFocusedFindingThreadRow(row: any): FocusedFindingThread {
  const confirmationState = parseJsonColumn<FocusedConfirmationState>(row.confirmation_state_json, buildEmptyFocusedConfirmationState());
  return {
    id: row.id,
    scanId: row.scan_id,
    caseId: row.case_id,
    executionId: row.execution_id,
    objectiveId: row.objective_id,
    findingKey: row.finding_key,
    title: row.title,
    family: normalizeFocusedCaseFamily(row.family),
    status: normalizeFocusedFindingThreadStatus(row.status),
    suspicionScore: Math.max(0, Math.min(100, Number(row.suspicion_score) || 0)),
    confirmationProgress: Math.max(0, Math.min(100, Number(row.confirmation_progress) || 0)),
    confidenceBand: normalizeFocusedFindingConfidenceBand(row.confidence_band),
    isPrimary: Number(row.is_primary) > 0,
    strongestSupportSummary: row.strongest_support_summary ?? null,
    strongestSuspiciousSignal: row.strongest_suspicious_signal ?? null,
    strongestBlockerSummary: row.strongest_blocker_summary ?? null,
    nextStepSummary: row.next_step_summary ?? null,
    stopReason: row.stop_reason ?? null,
    supportingSignals: parseJsonColumn<string[]>(row.supporting_signals_json, []),
    blockingConstraints: parseJsonColumn<string[]>(row.blocking_constraints_json, []),
    supportingEvidenceRefs: parseJsonColumn<any[]>(row.supporting_evidence_refs_json, []),
    blockingEvidenceRefs: parseJsonColumn<any[]>(row.blocking_evidence_refs_json, []),
    supportProvenance: parseJsonColumn<FocusedSupportProvenanceSummary | null>(row.support_provenance_json, null),
    requestEvidenceStory: parseJsonColumn<FocusedRequestEvidenceStory | null>(row.request_evidence_story_json, null),
    linkedTraceIds: parseJsonColumn<string[]>(row.linked_trace_ids_json, []),
    linkedVerdictIds: parseJsonColumn<string[]>(row.linked_verdict_ids_json, []),
    linkedInvestigationIds: parseJsonColumn<string[]>(row.linked_investigation_ids_json, []),
    confirmationState: {
      ...buildEmptyFocusedConfirmationState(),
      ...confirmationState,
      preferredRail: normalizeFocusedExecutionRail(confirmationState.preferredRail),
      allowedConfirmationKinds: Array.isArray(confirmationState.allowedConfirmationKinds)
        ? confirmationState.allowedConfirmationKinds.map((entry) => normalizeFocusedConfirmationKind(entry))
        : [],
      recommendedConfirmationKinds: Array.isArray(confirmationState.recommendedConfirmationKinds)
        ? confirmationState.recommendedConfirmationKinds.map((entry) => normalizeFocusedConfirmationKind(entry))
        : [],
      nextKind: confirmationState.nextKind ? normalizeFocusedConfirmationKind(confirmationState.nextKind) : null,
      readyForAdaptiveConfirmation: Boolean(confirmationState.readyForAdaptiveConfirmation),
      exhausted: Boolean(confirmationState.exhausted),
      steps: Array.isArray(confirmationState.steps)
        ? confirmationState.steps.map((step: any) => ({
            id: String(step?.id || ''),
            threadId: String(step?.threadId || row.id),
            kind: normalizeFocusedConfirmationKind(step?.kind),
            status: normalizeFocusedConfirmationStepStatus(step?.status),
            summary: String(step?.summary || '').trim(),
            actionType: step?.actionType ?? null,
            actionSummary: step?.actionSummary ?? null,
            evidenceIds: Array.isArray(step?.evidenceIds) ? step.evidenceIds.map((entry: unknown) => String(entry || '').trim()).filter(Boolean) : [],
            traceIds: Array.isArray(step?.traceIds) ? step.traceIds.map((entry: unknown) => String(entry || '').trim()).filter(Boolean) : [],
            startedAt: step?.startedAt ?? null,
            completedAt: step?.completedAt ?? null,
          } satisfies FocusedConfirmationStep)).filter((step) => step.id.length > 0 && step.summary.length > 0)
        : [],
    },
    publishedFindingId: row.published_finding_id ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapFocusedScanVerdictSummaryRow(row: any): FocusedScanVerdictSummary {
  const counts = {
    ...createEmptyFocusedVerdictCounts(),
    ...parseJsonColumn<Record<string, number>>(row.counts_by_verdict_json, {}),
  };

  return {
    scanId: row.scan_id,
    objectiveId: row.objective_id,
    overallVerdict: normalizeFocusedVerdictState(row.overall_verdict),
    totalCases: Number(row.total_cases) || 0,
    countsByVerdict: {
      pass: Number(counts.pass) || 0,
      fail: Number(counts.fail) || 0,
      inconclusive: Number(counts.inconclusive) || 0,
      needs_review: Number(counts.needs_review) || 0,
    },
    manualReviewRecommended: Number(row.manual_review_recommended) > 0,
    majorBlockers: parseJsonColumn<string[]>(row.major_blockers_json, []),
    latestVerdictAt: row.latest_verdict_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapFocusedInvestigationIssueRow(row: any): FocusedInvestigationIssue {
  const workaroundAttempts = parseJsonColumn<any[]>(row.workaround_attempts_json, []).map((attempt) => ({
    attemptedAt: attempt?.attemptedAt || row.detected_at,
    summary: String(attempt?.summary || '').trim(),
    outcome: normalizeFocusedWorkaroundOutcome(attempt?.outcome),
    details: attempt?.details ?? null,
    linkedEvidenceIds: Array.isArray(attempt?.linkedEvidenceIds) ? attempt.linkedEvidenceIds.filter((entry: unknown): entry is string => typeof entry === 'string') : [],
    linkedVerdictIds: Array.isArray(attempt?.linkedVerdictIds) ? attempt.linkedVerdictIds.filter((entry: unknown): entry is string => typeof entry === 'string') : [],
  })).filter((attempt) => attempt.summary.length > 0);

  return {
    id: row.id,
    scanId: row.scan_id,
    caseId: row.case_id,
    executionId: row.execution_id,
    objectiveId: row.objective_id,
    issueType: normalizeFocusedInvestigationIssueType(row.issue_type),
    issueTitle: row.issue_title,
    issueDetails: row.issue_details ?? null,
    issueStatus: normalizeFocusedInvestigationIssueStatus(row.issue_status),
    impact: normalizeFocusedInvestigationImpact(row.impact),
    source: row.source || 'system',
    correlation: parseJsonColumn<any | null>(row.correlation_json, null),
    linkedEvidenceIds: parseJsonColumn<string[]>(row.linked_evidence_ids_json, []),
    linkedVerdictIds: parseJsonColumn<string[]>(row.linked_verdict_ids_json, []),
    workaroundAttempts,
    expertFollowupHint: row.expert_followup_hint ?? null,
    assistanceSummary: row.assistance_summary ?? null,
    assistanceProfileKey: row.assistance_profile_key ?? null,
    assistanceProvider: row.assistance_provider ?? null,
    assistanceModel: row.assistance_model ?? null,
    detectedAt: row.detected_at,
    resolvedAt: row.resolved_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapFocusedScanBlockerSummaryRow(row: any): FocusedScanBlockerSummary {
  const statusCounts = {
    ...createEmptyFocusedInvestigationStatusCounts(),
    ...parseJsonColumn<Record<string, number>>(row.counts_by_status_json, {}),
  };
  const impactCounts = {
    ...createEmptyFocusedInvestigationImpactCounts(),
    ...parseJsonColumn<Record<string, number>>(row.counts_by_impact_json, {}),
  };
  const unresolvedByType = {
    ...createEmptyFocusedInvestigationTypeCounts(),
    ...parseJsonColumn<Record<string, number>>(row.unresolved_by_type_json, {}),
  };

  return {
    scanId: row.scan_id,
    objectiveId: row.objective_id,
    countsByStatus: {
      open: Number(statusCounts.open) || 0,
      resolved: Number(statusCounts.resolved) || 0,
      partially_resolved: Number(statusCounts.partially_resolved) || 0,
      unresolved: Number(statusCounts.unresolved) || 0,
      not_applicable: Number(statusCounts.not_applicable) || 0,
    },
    countsByImpact: {
      informational: Number(impactCounts.informational) || 0,
      degrading: Number(impactCounts.degrading) || 0,
      blocking: Number(impactCounts.blocking) || 0,
    },
    unresolvedByType: {
      scope_violation: Number(unresolvedByType.scope_violation) || 0,
      auth_session_drift: Number(unresolvedByType.auth_session_drift) || 0,
      missing_anchor: Number(unresolvedByType.missing_anchor) || 0,
      browser_state_mismatch: Number(unresolvedByType.browser_state_mismatch) || 0,
      evidence_insufficient: Number(unresolvedByType.evidence_insufficient) || 0,
      execution_budget_exhausted: Number(unresolvedByType.execution_budget_exhausted) || 0,
      request_replay_mismatch: Number(unresolvedByType.request_replay_mismatch) || 0,
      unexpected_navigation: Number(unresolvedByType.unexpected_navigation) || 0,
      unsupported_verification_primitive: Number(unresolvedByType.unsupported_verification_primitive) || 0,
      environment_instability: Number(unresolvedByType.environment_instability) || 0,
      contradictory_signals: Number(unresolvedByType.contradictory_signals) || 0,
      retry_failure: Number(unresolvedByType.retry_failure) || 0,
      blocked_flow: Number(unresolvedByType.blocked_flow) || 0,
    },
    repeatedBlockers: parseJsonColumn<string[]>(row.repeated_blockers_json, []),
    casesNeedingReview: parseJsonColumn<string[]>(row.cases_needing_review_json, []),
    latestMajorBlockerSummary: row.latest_major_blocker_summary ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapFocusedHistoricalCompareStateRow(row: any): FocusedHistoricalCompareState {
  return {
    scanId: row.scan_id,
    scopeType: row.scope_type,
    targetOrigin: row.target_origin || '',
    scopeIdentityKey: row.scope_identity_key || '',
    comparisonStatus: normalizeFocusedHistoricalCompareStatus(row.comparison_status),
    baselineScanId: row.baseline_scan_id ?? null,
    comparedAgainstScanId: row.compared_against_scan_id ?? null,
    firstObservedAt: row.first_observed_at ?? null,
    latestCompareAt: row.latest_compare_at ?? null,
    statusReason: row.status_reason ?? null,
    assistanceProfileKey: row.assistance_profile_key ?? null,
    assistanceProvider: row.assistance_provider ?? null,
    assistanceModel: row.assistance_model ?? null,
    assistanceNarrative: row.assistance_narrative ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapFocusedRemovedHistoricalCaseRow(row: any): FocusedRemovedHistoricalCase | null {
  if (!row || typeof row.previousCaseId !== 'string' || row.previousCaseId.trim().length === 0) {
    return null;
  }

  return {
    previousCaseId: row.previousCaseId,
    title: String(row.title || '').trim(),
    previousVerdict: row.previousVerdict ? normalizeFocusedVerdictState(row.previousVerdict) : null,
    previousEvidenceSufficiency: row.previousEvidenceSufficiency
      ? normalizeFocusedEvidenceSufficiencyState(row.previousEvidenceSufficiency)
      : null,
  };
}

function mapFocusedCaseHistoricalCompareRow(row: any): FocusedCaseHistoricalCompare {
  const blockerRecurrenceSource = parseJsonColumn<Record<string, unknown>>(row.blocker_recurrence_json, {});
  const blockerRecurrence = {
    ...createEmptyFocusedBlockerRecurrenceSummary(),
    ...blockerRecurrenceSource,
  };

  return {
    id: row.id,
    currentScanId: row.current_scan_id,
    currentCaseId: row.current_case_id,
    currentExecutionId: row.current_execution_id ?? null,
    caseIdentityKey: row.case_identity_key || '',
    caseVariantKey: row.case_variant_key || '',
    previousScanId: row.previous_scan_id ?? null,
    previousCaseId: row.previous_case_id ?? null,
    previousExecutionId: row.previous_execution_id ?? null,
    compareStatus: normalizeFocusedCaseCompareStatus(row.compare_status),
    historicalOutcome: row.historical_outcome ? normalizeFocusedHistoricalOutcome(row.historical_outcome) : null,
    priorVerdict: row.prior_verdict ? normalizeFocusedVerdictState(row.prior_verdict) : null,
    currentVerdict: row.current_verdict ? normalizeFocusedVerdictState(row.current_verdict) : null,
    verdictTransition: row.verdict_transition ? normalizeFocusedVerdictTransition(row.verdict_transition) : null,
    priorEvidenceSufficiency: row.prior_evidence_sufficiency
      ? normalizeFocusedEvidenceSufficiencyState(row.prior_evidence_sufficiency)
      : null,
    currentEvidenceSufficiency: row.current_evidence_sufficiency
      ? normalizeFocusedEvidenceSufficiencyState(row.current_evidence_sufficiency)
      : null,
    priorVerdictReason: row.prior_verdict_reason ?? null,
    currentVerdictReason: row.current_verdict_reason ?? null,
    priorEvidenceSummary: row.prior_evidence_summary ?? null,
    currentEvidenceSummary: row.current_evidence_summary ?? null,
    evidenceDriftClassification: row.evidence_drift_classification
      ? normalizeFocusedEvidenceDriftClassification(row.evidence_drift_classification)
      : null,
    blockerRecurrence: {
      recurringUnresolvedIssueFamilies: parseJsonColumn<any[]>(JSON.stringify(blockerRecurrence.recurringUnresolvedIssueFamilies || []), [])
        .map((entry) => normalizeFocusedInvestigationIssueType(entry)),
      resolvedIssueFamilies: parseJsonColumn<any[]>(JSON.stringify(blockerRecurrence.resolvedIssueFamilies || []), [])
        .map((entry) => normalizeFocusedInvestigationIssueType(entry)),
      newlyIntroducedIssueFamilies: parseJsonColumn<any[]>(JSON.stringify(blockerRecurrence.newlyIntroducedIssueFamilies || []), [])
        .map((entry) => normalizeFocusedInvestigationIssueType(entry)),
      recurringWorkaroundFailureFamilies: parseJsonColumn<any[]>(JSON.stringify(blockerRecurrence.recurringWorkaroundFailureFamilies || []), [])
        .map((entry) => normalizeFocusedInvestigationIssueType(entry)),
      blockingCountDelta: Number(blockerRecurrence.blockingCountDelta) || 0,
      degradingCountDelta: Number(blockerRecurrence.degradingCountDelta) || 0,
      notes: Array.isArray(blockerRecurrence.notes)
        ? blockerRecurrence.notes.filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
        : [],
    },
    compareNarrative: row.compare_narrative ?? null,
    assistanceProfileKey: row.assistance_profile_key ?? null,
    assistanceProvider: row.assistance_provider ?? null,
    assistanceModel: row.assistance_model ?? null,
    latestCompareAt: row.latest_compare_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapFocusedHistoricalCompareSummaryRow(row: any): FocusedHistoricalCompareSummary {
  const transitionCounts = {
    ...createEmptyFocusedVerdictTransitionCounts(),
    ...parseJsonColumn<Record<string, number>>(row.counts_by_verdict_transition_json, {}),
  };

  return {
    scanId: row.scan_id,
    baselineScanId: row.baseline_scan_id ?? null,
    comparedAgainstScanId: row.compared_against_scan_id ?? null,
    comparisonStatus: normalizeFocusedHistoricalCompareStatus(row.comparison_status),
    overallChangeClassification: normalizeFocusedOverallChangeClassification(row.overall_change_classification),
    countsByVerdictTransition: {
      pass_to_pass: Number(transitionCounts.pass_to_pass) || 0,
      pass_to_fail: Number(transitionCounts.pass_to_fail) || 0,
      pass_to_inconclusive: Number(transitionCounts.pass_to_inconclusive) || 0,
      pass_to_needs_review: Number(transitionCounts.pass_to_needs_review) || 0,
      fail_to_pass: Number(transitionCounts.fail_to_pass) || 0,
      fail_to_fail: Number(transitionCounts.fail_to_fail) || 0,
      fail_to_inconclusive: Number(transitionCounts.fail_to_inconclusive) || 0,
      fail_to_needs_review: Number(transitionCounts.fail_to_needs_review) || 0,
      inconclusive_to_pass: Number(transitionCounts.inconclusive_to_pass) || 0,
      inconclusive_to_fail: Number(transitionCounts.inconclusive_to_fail) || 0,
      inconclusive_to_inconclusive: Number(transitionCounts.inconclusive_to_inconclusive) || 0,
      inconclusive_to_needs_review: Number(transitionCounts.inconclusive_to_needs_review) || 0,
      needs_review_to_pass: Number(transitionCounts.needs_review_to_pass) || 0,
      needs_review_to_fail: Number(transitionCounts.needs_review_to_fail) || 0,
      needs_review_to_inconclusive: Number(transitionCounts.needs_review_to_inconclusive) || 0,
      needs_review_to_needs_review: Number(transitionCounts.needs_review_to_needs_review) || 0,
    },
    improvedCount: Number(row.improved_count) || 0,
    regressedCount: Number(row.regressed_count) || 0,
    unchangedCount: Number(row.unchanged_count) || 0,
    weakerConfidenceCount: Number(row.weaker_confidence_count) || 0,
    strongerConfidenceCount: Number(row.stronger_confidence_count) || 0,
    newlyIntroducedCount: Number(row.newly_introduced_count) || 0,
    notComparableCount: Number(row.not_comparable_count) || 0,
    removedPriorCaseCount: Number(row.removed_prior_case_count) || 0,
    improvedCases: parseJsonColumn<string[]>(row.improved_cases_json, []),
    regressedCases: parseJsonColumn<string[]>(row.regressed_cases_json, []),
    unstableCases: parseJsonColumn<string[]>(row.unstable_cases_json, []),
    repeatedBlockerFamilies: parseJsonColumn<any[]>(row.repeated_blocker_families_json, [])
      .map((entry) => normalizeFocusedInvestigationIssueType(entry)),
    newBlockerFamilies: parseJsonColumn<any[]>(row.new_blocker_families_json, [])
      .map((entry) => normalizeFocusedInvestigationIssueType(entry)),
    resolvedBlockerFamilies: parseJsonColumn<any[]>(row.resolved_blocker_families_json, [])
      .map((entry) => normalizeFocusedInvestigationIssueType(entry)),
    removedPriorCases: parseJsonColumn<any[]>(row.removed_prior_cases_json, [])
      .map((entry) => mapFocusedRemovedHistoricalCaseRow(entry))
      .filter((entry): entry is FocusedRemovedHistoricalCase => !!entry),
    stabilityNotes: parseJsonColumn<string[]>(row.stability_notes_json, []),
    manualReviewRecommended: Number(row.manual_review_recommended) > 0,
    latestCompareAt: row.latest_compare_at ?? null,
    assistanceProfileKey: row.assistance_profile_key ?? null,
    assistanceProvider: row.assistance_provider ?? null,
    assistanceModel: row.assistance_model ?? null,
    compareNarrative: row.compare_narrative ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export const createFocusedTestCaseExecution = (execution: FocusedTestCaseExecution) => {
  return db.prepare(`
    INSERT INTO focused_test_case_executions (
      id,
      scan_id,
      case_id,
      objective_id,
      execution_state,
      execution_profile_key,
      run_reason,
      notes_summary,
      error_message,
      request_actions_used,
      browser_actions_used,
      browser_session_id,
      started_at,
      completed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?)
  `).run(
    execution.id,
    execution.scanId,
    execution.caseId,
    execution.objectiveId,
    execution.executionState,
    execution.executionProfileKey,
    execution.runReason ?? null,
    execution.notesSummary ?? null,
    execution.errorMessage ?? null,
    execution.requestActionsUsed ?? 0,
    execution.browserActionsUsed ?? 0,
    execution.browserSessionId ?? null,
    execution.startedAt ?? null,
    execution.completedAt ?? null,
  );
};

export const updateFocusedTestCaseExecution = (
  scanId: string,
  caseId: string,
  executionId: string,
  updates: {
    executionState?: string;
    executionProfileKey?: string;
    runReason?: string | null;
    notesSummary?: string | null;
    errorMessage?: string | null;
    requestActionsUsed?: number;
    browserActionsUsed?: number;
    browserSessionId?: string | null;
    completedAt?: string | null;
  },
) => {
  const assignments: string[] = [];
  const values: any[] = [];

  if (updates.executionState !== undefined) {
    assignments.push('execution_state = ?');
    values.push(normalizeFocusedExecutionState(updates.executionState));
  }
  if (updates.executionProfileKey !== undefined) {
    assignments.push('execution_profile_key = ?');
    values.push(updates.executionProfileKey);
  }
  if (updates.runReason !== undefined) {
    assignments.push('run_reason = ?');
    values.push(updates.runReason ?? null);
  }
  if (updates.notesSummary !== undefined) {
    assignments.push('notes_summary = ?');
    values.push(updates.notesSummary ?? null);
  }
  if (updates.errorMessage !== undefined) {
    assignments.push('error_message = ?');
    values.push(updates.errorMessage ?? null);
  }
  if (updates.requestActionsUsed !== undefined) {
    assignments.push('request_actions_used = ?');
    values.push(updates.requestActionsUsed);
  }
  if (updates.browserActionsUsed !== undefined) {
    assignments.push('browser_actions_used = ?');
    values.push(updates.browserActionsUsed);
  }
  if (updates.browserSessionId !== undefined) {
    assignments.push('browser_session_id = ?');
    values.push(updates.browserSessionId ?? null);
  }
  if (updates.completedAt !== undefined) {
    assignments.push('completed_at = ?');
    values.push(updates.completedAt ?? null);
  }

  if (assignments.length === 0) {
    return getFocusedTestCaseExecutionById(scanId, caseId, executionId);
  }

  assignments.push('updated_at = CURRENT_TIMESTAMP');
  db.prepare(`
    UPDATE focused_test_case_executions
    SET ${assignments.join(', ')}
    WHERE scan_id = ? AND case_id = ? AND id = ?
  `).run(...values, scanId, caseId, executionId);

  return getFocusedTestCaseExecutionById(scanId, caseId, executionId);
};

export const getFocusedTestCaseExecutionById = (scanId: string, caseId: string, executionId: string): FocusedTestCaseExecution | null => {
  const row = db.prepare(`
    SELECT *
    FROM focused_test_case_executions
    WHERE scan_id = ? AND case_id = ? AND id = ?
  `).get(scanId, caseId, executionId) as any;

  return row ? mapFocusedTestCaseExecutionRow(row) : null;
};

export const listFocusedTestCaseExecutionsByCase = (scanId: string, caseId: string): FocusedTestCaseExecution[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_executions
    WHERE scan_id = ? AND case_id = ?
    ORDER BY COALESCE(started_at, created_at) DESC, created_at DESC, id DESC
  `).all(scanId, caseId) as any[];

  return rows.map(mapFocusedTestCaseExecutionRow);
};

export const getLatestFocusedTestCaseExecution = (scanId: string, caseId: string): FocusedTestCaseExecution | null => {
  const row = db.prepare(`
    SELECT *
    FROM focused_test_case_executions
    WHERE scan_id = ? AND case_id = ?
    ORDER BY COALESCE(started_at, created_at) DESC, created_at DESC, id DESC
    LIMIT 1
  `).get(scanId, caseId) as any;

  return row ? mapFocusedTestCaseExecutionRow(row) : null;
};

export const createFocusedExecutionTraceEntry = (entry: FocusedExecutionTraceEntry) => {
  return db.prepare(`
    INSERT INTO focused_test_case_execution_trace_entries (
      id,
      scan_id,
      case_id,
      execution_id,
      timestamp,
      action_type,
      action_summary,
      target_summary,
      request_summary_json,
      response_summary_json,
      reasoning_note,
      next_step_rationale,
      stop_reason,
      retry_reason,
      rail,
      tool_summary,
      linked_evidence_ids_json
    ) VALUES (?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    entry.id,
    entry.scanId,
    entry.caseId,
    entry.executionId,
    entry.timestamp ?? null,
    normalizeFocusedExecutionTraceActionType(entry.actionType),
    entry.actionSummary,
    entry.targetSummary ?? null,
    entry.requestSummary ? JSON.stringify(entry.requestSummary) : null,
    entry.responseSummary ? JSON.stringify(entry.responseSummary) : null,
    entry.reasoningNote ?? null,
    entry.nextStepRationale ?? null,
    entry.stopReason ?? null,
    entry.retryReason ?? null,
    normalizeFocusedExecutionRail(entry.rail),
    entry.toolSummary ?? null,
    entry.linkedEvidenceIds?.length ? JSON.stringify(entry.linkedEvidenceIds) : null,
  );
};

export const listFocusedExecutionTraceEntriesByExecution = (scanId: string, caseId: string, executionId: string): FocusedExecutionTraceEntry[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_execution_trace_entries
    WHERE scan_id = ? AND case_id = ? AND execution_id = ?
    ORDER BY timestamp ASC, created_at ASC, id ASC
  `).all(scanId, caseId, executionId) as any[];

  return rows.map(mapFocusedExecutionTraceEntryRow);
};

export const createFocusedReasoningTraceEntry = (entry: FocusedReasoningTraceEntry) => {
  return db.prepare(`
    INSERT INTO focused_reasoning_trace_entries (
      id,
      scan_id,
      objective_id,
      case_id,
      execution_id,
      timestamp,
      stage,
      entry_type,
      rail,
      case_family,
      summary,
      observation_summary,
      hypothesis_rationale_summary,
      action_selection_rationale,
      request_response_impact_summary,
      browser_state_impact_summary,
      confidence_shift_summary,
      stop_retry_block_rationale,
      linked_evidence_ids_json,
      linked_request_context_keys_json,
      context_influence_json
    ) VALUES (?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    entry.id,
    entry.scanId,
    entry.objectiveId,
    entry.caseId ?? null,
    entry.executionId ?? null,
    entry.timestamp ?? null,
    normalizeFocusedReasoningStage(entry.stage),
    normalizeFocusedReasoningEntryType(entry.entryType),
    normalizeFocusedReasoningRail(entry.rail),
    entry.caseFamily ? normalizeFocusedCaseFamily(entry.caseFamily) : null,
    entry.summary,
    entry.observationSummary ?? null,
    entry.hypothesisRationaleSummary ?? null,
    entry.actionSelectionRationale ?? null,
    entry.requestResponseImpactSummary ?? null,
    entry.browserStateImpactSummary ?? null,
    entry.confidenceShiftSummary ?? null,
    entry.stopRetryBlockRationale ?? null,
    entry.linkedEvidenceIds?.length ? JSON.stringify(entry.linkedEvidenceIds) : null,
    entry.linkedRequestContextKeys?.length ? JSON.stringify(entry.linkedRequestContextKeys) : null,
    entry.contextInfluence?.length ? JSON.stringify(entry.contextInfluence) : null,
  );
};

export const listFocusedReasoningTraceEntriesByScan = (scanId: string, limit = 200): FocusedReasoningTraceEntry[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_reasoning_trace_entries
    WHERE scan_id = ?
    ORDER BY timestamp DESC, created_at DESC, id DESC
    LIMIT ?
  `).all(scanId, Math.max(limit, 1)) as any[];

  return rows.map(mapFocusedReasoningTraceEntryRow).reverse();
};

export const listFocusedReasoningTraceEntriesByCase = (scanId: string, caseId: string): FocusedReasoningTraceEntry[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_reasoning_trace_entries
    WHERE scan_id = ? AND case_id = ?
    ORDER BY timestamp ASC, created_at ASC, id ASC
  `).all(scanId, caseId) as any[];

  return rows.map(mapFocusedReasoningTraceEntryRow);
};

export const listFocusedReasoningTraceEntriesByExecution = (
  scanId: string,
  caseId: string,
  executionId: string,
): FocusedReasoningTraceEntry[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_reasoning_trace_entries
    WHERE scan_id = ? AND case_id = ? AND execution_id = ?
    ORDER BY timestamp ASC, created_at ASC, id ASC
  `).all(scanId, caseId, executionId) as any[];

  return rows.map(mapFocusedReasoningTraceEntryRow);
};

export const createEvidenceBundle = (bundle: EvidenceBundle) => {
  return db.prepare(`
    INSERT INTO focused_test_case_evidence_bundles (
      id,
      scan_id,
      case_id,
      execution_id,
      summary,
      source,
      captured_at,
      request_ref_json,
      response_ref_json,
      response_diff_summary_json,
      screenshot_ref_json,
      browser_state_json,
      related_evidence_ids_json,
      execution_notes,
      provenance_json,
      scope_violation_json
    ) VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    bundle.id,
    bundle.scanId,
    bundle.caseId,
    bundle.executionId,
    bundle.summary,
    bundle.source,
    bundle.capturedAt ?? null,
    bundle.requestRef ? JSON.stringify(bundle.requestRef) : null,
    bundle.responseRef ? JSON.stringify(bundle.responseRef) : null,
    bundle.responseDiffSummary ? JSON.stringify(bundle.responseDiffSummary) : null,
    bundle.screenshotRef ? JSON.stringify(bundle.screenshotRef) : null,
    bundle.browserState ? JSON.stringify(bundle.browserState) : null,
    bundle.relatedEvidenceIds ? JSON.stringify(bundle.relatedEvidenceIds) : null,
    bundle.executionNotes ?? null,
    bundle.provenance ? JSON.stringify(bundle.provenance) : null,
    bundle.scopeViolation ? JSON.stringify(bundle.scopeViolation) : null,
  );
};

export const listEvidenceBundlesByExecution = (scanId: string, caseId: string, executionId: string): EvidenceBundle[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_evidence_bundles
    WHERE scan_id = ? AND case_id = ? AND execution_id = ?
    ORDER BY captured_at ASC, created_at ASC, id ASC
  `).all(scanId, caseId, executionId) as any[];

  return rows.map(mapEvidenceBundleRow);
};

export const listEvidenceBundlesByCase = (scanId: string, caseId: string): EvidenceBundle[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_evidence_bundles
    WHERE scan_id = ? AND case_id = ?
    ORDER BY captured_at ASC, created_at ASC, id ASC
  `).all(scanId, caseId) as any[];

  return rows.map(mapEvidenceBundleRow);
};

export const upsertFocusedCaseVerdict = (verdict: FocusedCaseVerdict) => {
  db.prepare(`
    INSERT INTO focused_test_case_verdicts (
      id,
      scan_id,
      case_id,
      execution_id,
      objective_id,
      verdict_state,
      verdict_reason,
      evidence_sufficiency_state,
      evidence_sufficiency_report_json,
      supporting_evidence_refs_json,
      support_provenance_json,
      request_evidence_story_json,
      interpretation_summary_json,
      scope_violation_impact_json,
      execution_snapshot_json,
      assistance_profile_key,
      assistance_provider,
      assistance_model,
      assistance_narrative,
      verdict_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
    ON CONFLICT(scan_id, case_id, execution_id) DO UPDATE SET
      verdict_state = excluded.verdict_state,
      verdict_reason = excluded.verdict_reason,
      evidence_sufficiency_state = excluded.evidence_sufficiency_state,
      evidence_sufficiency_report_json = excluded.evidence_sufficiency_report_json,
      supporting_evidence_refs_json = excluded.supporting_evidence_refs_json,
      support_provenance_json = excluded.support_provenance_json,
      request_evidence_story_json = excluded.request_evidence_story_json,
      interpretation_summary_json = excluded.interpretation_summary_json,
      scope_violation_impact_json = excluded.scope_violation_impact_json,
      execution_snapshot_json = excluded.execution_snapshot_json,
      assistance_profile_key = excluded.assistance_profile_key,
      assistance_provider = excluded.assistance_provider,
      assistance_model = excluded.assistance_model,
      assistance_narrative = excluded.assistance_narrative,
      verdict_at = excluded.verdict_at,
      updated_at = CURRENT_TIMESTAMP
  `).run(
    verdict.id,
    verdict.scanId,
    verdict.caseId,
    verdict.executionId,
    verdict.objectiveId,
    verdict.verdictState,
    verdict.verdictReason,
    verdict.evidenceSufficiency.state,
    JSON.stringify(verdict.evidenceSufficiency),
    JSON.stringify(verdict.supportingEvidenceRefs || []),
    verdict.supportProvenance ? JSON.stringify(verdict.supportProvenance) : null,
    verdict.requestEvidenceStory ? JSON.stringify(verdict.requestEvidenceStory) : null,
    JSON.stringify(verdict.interpretationSummary),
    JSON.stringify(verdict.scopeViolationImpact),
    JSON.stringify(verdict.executionSnapshot),
    verdict.assistanceProfileKey ?? null,
    verdict.assistanceProvider ?? null,
    verdict.assistanceModel ?? null,
    verdict.assistanceNarrative ?? null,
    verdict.verdictAt ?? null,
  );

  return getFocusedCaseVerdictByExecution(verdict.scanId, verdict.caseId, verdict.executionId);
};

export const getFocusedCaseVerdictByExecution = (scanId: string, caseId: string, executionId: string): FocusedCaseVerdict | null => {
  const row = db.prepare(`
    SELECT *
    FROM focused_test_case_verdicts
    WHERE scan_id = ? AND case_id = ? AND execution_id = ?
  `).get(scanId, caseId, executionId) as any;

  return row ? mapFocusedCaseVerdictRow(row) : null;
};

export const listFocusedCaseVerdictsByCase = (scanId: string, caseId: string): FocusedCaseVerdict[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_verdicts
    WHERE scan_id = ? AND case_id = ?
    ORDER BY COALESCE(verdict_at, created_at) DESC, created_at DESC, id DESC
  `).all(scanId, caseId) as any[];

  return rows.map(mapFocusedCaseVerdictRow);
};

export const listFocusedCaseVerdictsByScan = (scanId: string): FocusedCaseVerdict[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_verdicts
    WHERE scan_id = ?
    ORDER BY COALESCE(verdict_at, created_at) DESC, created_at DESC, id DESC
  `).all(scanId) as any[];

  return rows.map(mapFocusedCaseVerdictRow);
};

export const listLatestFocusedCaseVerdictsByScan = (scanId: string): FocusedCaseVerdict[] => {
  const verdicts = listFocusedCaseVerdictsByScan(scanId);
  const deduped = new Map<string, FocusedCaseVerdict>();

  for (const verdict of verdicts) {
    if (!deduped.has(verdict.caseId)) {
      deduped.set(verdict.caseId, verdict);
    }
  }

  return [...deduped.values()];
};

export const getLatestFocusedCaseVerdictByCase = (scanId: string, caseId: string): FocusedCaseVerdict | null => {
  const verdicts = listFocusedCaseVerdictsByCase(scanId, caseId);
  return verdicts[0] || null;
};

export const upsertFocusedCaseFinding = (finding: FocusedCaseFinding) => {
  db.prepare(`
    INSERT INTO focused_test_case_findings (
      id,
      scan_id,
      case_id,
      execution_id,
      objective_id,
      finding_key,
      title,
      family,
      status,
      suspicion_score,
      confirmation_progress,
      confidence_band,
      rank_order,
      is_primary,
      strongest_support_summary,
      blocking_constraint_summary,
      next_step_summary,
      supporting_signals_json,
      blocking_constraints_json,
      supporting_evidence_refs_json,
      support_provenance_json,
      request_evidence_story_json,
      linked_verdict_ids_json,
      linked_investigation_ids_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(scan_id, case_id, execution_id, finding_key) DO UPDATE SET
      title = excluded.title,
      family = excluded.family,
      status = excluded.status,
      suspicion_score = excluded.suspicion_score,
      confirmation_progress = excluded.confirmation_progress,
      confidence_band = excluded.confidence_band,
      rank_order = excluded.rank_order,
      is_primary = excluded.is_primary,
      strongest_support_summary = excluded.strongest_support_summary,
      blocking_constraint_summary = excluded.blocking_constraint_summary,
      next_step_summary = excluded.next_step_summary,
      supporting_signals_json = excluded.supporting_signals_json,
      blocking_constraints_json = excluded.blocking_constraints_json,
      supporting_evidence_refs_json = excluded.supporting_evidence_refs_json,
      support_provenance_json = excluded.support_provenance_json,
      request_evidence_story_json = excluded.request_evidence_story_json,
      linked_verdict_ids_json = excluded.linked_verdict_ids_json,
      linked_investigation_ids_json = excluded.linked_investigation_ids_json,
      updated_at = CURRENT_TIMESTAMP
  `).run(
    finding.id,
    finding.scanId,
    finding.caseId,
    finding.executionId,
    finding.objectiveId,
    finding.findingKey,
    finding.title,
    finding.family,
    finding.status,
    Math.max(0, Math.min(100, Math.round(Number(finding.suspicionScore) || 0))),
    Math.max(0, Math.min(100, Math.round(Number(finding.confirmationProgress) || 0))),
    finding.confidenceBand,
    Number(finding.rankOrder) || 0,
    finding.isPrimary ? 1 : 0,
    finding.strongestSupportSummary,
    finding.blockingConstraintSummary ?? null,
    finding.nextStepSummary ?? null,
    JSON.stringify(finding.supportingSignals || []),
    JSON.stringify(finding.blockingConstraints || []),
    JSON.stringify(finding.supportingEvidenceRefs || []),
    finding.supportProvenance ? JSON.stringify(finding.supportProvenance) : null,
    finding.requestEvidenceStory ? JSON.stringify(finding.requestEvidenceStory) : null,
    JSON.stringify(finding.linkedVerdictIds || []),
    JSON.stringify(finding.linkedInvestigationIds || []),
  );
};

export const listFocusedCaseFindingsByExecution = (scanId: string, caseId: string, executionId: string): FocusedCaseFinding[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_findings
    WHERE scan_id = ? AND case_id = ? AND execution_id = ?
    ORDER BY is_primary DESC, rank_order ASC, suspicion_score DESC, confirmation_progress DESC, title ASC
  `).all(scanId, caseId, executionId) as any[];

  return rows.map(mapFocusedCaseFindingRow);
};

export const listFocusedCaseFindingsByCase = (scanId: string, caseId: string): FocusedCaseFinding[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_findings
    WHERE scan_id = ? AND case_id = ?
    ORDER BY updated_at DESC, created_at DESC, is_primary DESC, rank_order ASC, title ASC
  `).all(scanId, caseId) as any[];

  return rows.map(mapFocusedCaseFindingRow);
};

export const listFocusedCaseFindingsByScan = (scanId: string): FocusedCaseFinding[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_findings
    WHERE scan_id = ?
    ORDER BY updated_at DESC, created_at DESC, is_primary DESC, rank_order ASC, title ASC
  `).all(scanId) as any[];

  return rows.map(mapFocusedCaseFindingRow);
};

export const listLatestFocusedCaseFindingsByCase = (scanId: string, caseId: string): FocusedCaseFinding[] => {
  const latestExecution = getLatestFocusedTestCaseExecution(scanId, caseId);
  if (!latestExecution) {
    return [];
  }

  return listFocusedCaseFindingsByExecution(scanId, caseId, latestExecution.id);
};

export const listLatestFocusedCaseFindingsByScan = (scanId: string): FocusedCaseFinding[] => {
  const findings: FocusedCaseFinding[] = [];
  for (const testCase of listFocusedTestCasesByScan(scanId)) {
    findings.push(...listLatestFocusedCaseFindingsByCase(scanId, testCase.id));
  }

  return findings.sort((left, right) => {
    if (left.caseId !== right.caseId) {
      return left.caseId.localeCompare(right.caseId);
    }
    if ((left.isPrimary ? 1 : 0) !== (right.isPrimary ? 1 : 0)) {
      return Number(right.isPrimary) - Number(left.isPrimary);
    }
    if (left.rankOrder !== right.rankOrder) {
      return left.rankOrder - right.rankOrder;
    }
    if (left.suspicionScore !== right.suspicionScore) {
      return right.suspicionScore - left.suspicionScore;
    }
    if (left.confirmationProgress !== right.confirmationProgress) {
      return right.confirmationProgress - left.confirmationProgress;
    }
    return left.title.localeCompare(right.title);
  });
};

export const listLatestPrimaryFocusedCaseFindingsByScan = (scanId: string): FocusedCaseFinding[] => {
  return listLatestFocusedCaseFindingsByScan(scanId)
    .filter((finding) => finding.isPrimary)
    .sort((left, right) => {
      const statusRank: Record<FocusedFindingStatus, number> = {
        confirmed: 0,
        likely: 1,
        suspicious: 2,
        inconclusive: 3,
        not_confirmed: 4,
      };
      if (statusRank[left.status] !== statusRank[right.status]) {
        return statusRank[left.status] - statusRank[right.status];
      }
      if (left.suspicionScore !== right.suspicionScore) {
        return right.suspicionScore - left.suspicionScore;
      }
      if (left.confirmationProgress !== right.confirmationProgress) {
        return right.confirmationProgress - left.confirmationProgress;
      }
      return left.title.localeCompare(right.title);
    });
};

export const getLatestPrimaryFocusedCaseFindingByCase = (scanId: string, caseId: string): FocusedCaseFinding | null => {
  const findings = listLatestFocusedCaseFindingsByCase(scanId, caseId);
  return findings.find((entry) => entry.isPrimary) || findings[0] || null;
};

export const upsertFocusedFindingThread = (thread: FocusedFindingThread) => {
  db.prepare(`
    INSERT INTO focused_test_case_finding_threads (
      id,
      scan_id,
      case_id,
      execution_id,
      objective_id,
      finding_key,
      title,
      family,
      status,
      suspicion_score,
      confirmation_progress,
      confidence_band,
      is_primary,
      strongest_support_summary,
      strongest_suspicious_signal,
      strongest_blocker_summary,
      next_step_summary,
      stop_reason,
      supporting_signals_json,
      blocking_constraints_json,
      supporting_evidence_refs_json,
      blocking_evidence_refs_json,
      support_provenance_json,
      request_evidence_story_json,
      linked_trace_ids_json,
      linked_verdict_ids_json,
      linked_investigation_ids_json,
      confirmation_state_json,
      published_finding_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(scan_id, case_id, execution_id, finding_key) DO UPDATE SET
      title = excluded.title,
      family = excluded.family,
      status = excluded.status,
      suspicion_score = excluded.suspicion_score,
      confirmation_progress = excluded.confirmation_progress,
      confidence_band = excluded.confidence_band,
      is_primary = excluded.is_primary,
      strongest_support_summary = excluded.strongest_support_summary,
      strongest_suspicious_signal = excluded.strongest_suspicious_signal,
      strongest_blocker_summary = excluded.strongest_blocker_summary,
      next_step_summary = excluded.next_step_summary,
      stop_reason = excluded.stop_reason,
      supporting_signals_json = excluded.supporting_signals_json,
      blocking_constraints_json = excluded.blocking_constraints_json,
      supporting_evidence_refs_json = excluded.supporting_evidence_refs_json,
      blocking_evidence_refs_json = excluded.blocking_evidence_refs_json,
      support_provenance_json = excluded.support_provenance_json,
      request_evidence_story_json = excluded.request_evidence_story_json,
      linked_trace_ids_json = excluded.linked_trace_ids_json,
      linked_verdict_ids_json = excluded.linked_verdict_ids_json,
      linked_investigation_ids_json = excluded.linked_investigation_ids_json,
      confirmation_state_json = excluded.confirmation_state_json,
      published_finding_id = excluded.published_finding_id,
      updated_at = CURRENT_TIMESTAMP
  `).run(
    thread.id,
    thread.scanId,
    thread.caseId,
    thread.executionId,
    thread.objectiveId,
    thread.findingKey,
    thread.title,
    thread.family,
    thread.status,
    Math.max(0, Math.min(100, Math.round(Number(thread.suspicionScore) || 0))),
    Math.max(0, Math.min(100, Math.round(Number(thread.confirmationProgress) || 0))),
    thread.confidenceBand,
    thread.isPrimary ? 1 : 0,
    thread.strongestSupportSummary ?? null,
    thread.strongestSuspiciousSignal ?? null,
    thread.strongestBlockerSummary ?? null,
    thread.nextStepSummary ?? null,
    thread.stopReason ?? null,
    JSON.stringify(thread.supportingSignals || []),
    JSON.stringify(thread.blockingConstraints || []),
    JSON.stringify(thread.supportingEvidenceRefs || []),
    JSON.stringify(thread.blockingEvidenceRefs || []),
    thread.supportProvenance ? JSON.stringify(thread.supportProvenance) : null,
    thread.requestEvidenceStory ? JSON.stringify(thread.requestEvidenceStory) : null,
    JSON.stringify(thread.linkedTraceIds || []),
    JSON.stringify(thread.linkedVerdictIds || []),
    JSON.stringify(thread.linkedInvestigationIds || []),
    JSON.stringify(thread.confirmationState || buildEmptyFocusedConfirmationState()),
    thread.publishedFindingId ?? null,
  );

  return getFocusedFindingThreadByExecution(thread.scanId, thread.caseId, thread.executionId, thread.findingKey);
};

export const getFocusedFindingThreadByExecution = (scanId: string, caseId: string, executionId: string, findingKey: string): FocusedFindingThread | null => {
  const row = db.prepare(`
    SELECT *
    FROM focused_test_case_finding_threads
    WHERE scan_id = ? AND case_id = ? AND execution_id = ? AND finding_key = ?
  `).get(scanId, caseId, executionId, findingKey) as any;

  return row ? mapFocusedFindingThreadRow(row) : null;
};

export const listFocusedFindingThreadsByExecution = (scanId: string, caseId: string, executionId: string): FocusedFindingThread[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_finding_threads
    WHERE scan_id = ? AND case_id = ? AND execution_id = ?
    ORDER BY is_primary DESC, suspicion_score DESC, confirmation_progress DESC, title ASC
  `).all(scanId, caseId, executionId) as any[];

  return rows.map(mapFocusedFindingThreadRow);
};

export const listFocusedFindingThreadsByCase = (scanId: string, caseId: string): FocusedFindingThread[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_finding_threads
    WHERE scan_id = ? AND case_id = ?
    ORDER BY updated_at DESC, created_at DESC, is_primary DESC, suspicion_score DESC, confirmation_progress DESC, title ASC
  `).all(scanId, caseId) as any[];

  return rows.map(mapFocusedFindingThreadRow);
};

export const listFocusedFindingThreadsByScan = (scanId: string): FocusedFindingThread[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_finding_threads
    WHERE scan_id = ?
    ORDER BY updated_at DESC, created_at DESC, is_primary DESC, suspicion_score DESC, confirmation_progress DESC, title ASC
  `).all(scanId) as any[];

  return rows.map(mapFocusedFindingThreadRow);
};

export const listLatestFocusedFindingThreadsByCase = (scanId: string, caseId: string): FocusedFindingThread[] => {
  const latestExecution = getLatestFocusedTestCaseExecution(scanId, caseId);
  if (!latestExecution) {
    return [];
  }
  return listFocusedFindingThreadsByExecution(scanId, caseId, latestExecution.id);
};

export const listLatestFocusedFindingThreadsByScan = (scanId: string): FocusedFindingThread[] => {
  const threads: FocusedFindingThread[] = [];
  for (const testCase of listFocusedTestCasesByScan(scanId)) {
    threads.push(...listLatestFocusedFindingThreadsByCase(scanId, testCase.id));
  }
  return threads.sort((left, right) => {
    if (left.caseId !== right.caseId) {
      return left.caseId.localeCompare(right.caseId);
    }
    if ((left.isPrimary ? 1 : 0) !== (right.isPrimary ? 1 : 0)) {
      return Number(right.isPrimary) - Number(left.isPrimary);
    }
    if (left.suspicionScore !== right.suspicionScore) {
      return right.suspicionScore - left.suspicionScore;
    }
    if (left.confirmationProgress !== right.confirmationProgress) {
      return right.confirmationProgress - left.confirmationProgress;
    }
    return left.title.localeCompare(right.title);
  });
};

export const listLatestPrimaryFocusedFindingThreadsByScan = (scanId: string): FocusedFindingThread[] => {
  return listLatestFocusedFindingThreadsByScan(scanId)
    .filter((thread) => thread.isPrimary)
    .sort((left, right) => {
      if (left.suspicionScore !== right.suspicionScore) {
        return right.suspicionScore - left.suspicionScore;
      }
      if (left.confirmationProgress !== right.confirmationProgress) {
        return right.confirmationProgress - left.confirmationProgress;
      }
      return left.title.localeCompare(right.title);
    });
};

export const getLatestPrimaryFocusedFindingThreadByCase = (scanId: string, caseId: string): FocusedFindingThread | null => {
  const threads = listLatestFocusedFindingThreadsByCase(scanId, caseId);
  return threads.find((entry) => entry.isPrimary) || threads[0] || null;
};

export const getFocusedScanFindingSummary = (scanId: string): FocusedScanFindingSummary | null => {
  const objective = getFocusedTestObjective(scanId);
  if (!objective) {
    return null;
  }

  const latestFindings = listLatestFocusedCaseFindingsByScan(scanId);
  const primaryFindings = latestFindings.filter((finding) => finding.isPrimary);
  const primaryThreads = listLatestPrimaryFocusedFindingThreadsByScan(scanId);
  const effectivePrimaryEntries = primaryFindings.length > 0
    ? primaryFindings.map((finding) => ({
        status: finding.status,
        updatedAt: finding.updatedAt || finding.createdAt || null,
      }))
    : primaryThreads.map((thread) => ({
        status: thread.suspicionScore >= 70
          ? 'likely'
          : thread.suspicionScore >= 45
            ? 'suspicious'
            : thread.blockingConstraints.length > 0 || thread.status === 'blocked'
              ? 'inconclusive'
              : 'not_confirmed',
        updatedAt: thread.updatedAt || thread.createdAt || null,
      }));
  const countsByStatus = createEmptyFocusedFindingStatusCounts();
  let latestFindingAt: string | null = null;

  for (const finding of effectivePrimaryEntries) {
    countsByStatus[finding.status as FocusedFindingStatus] += 1;
    const timestamp = finding.updatedAt || null;
    if (timestamp && (!latestFindingAt || timestamp > latestFindingAt)) {
      latestFindingAt = timestamp;
    }
  }

  return {
    scanId,
    objectiveId: objective.id,
    totalFindings: latestFindings.length > 0 ? latestFindings.length : primaryThreads.length,
    primaryFindings: effectivePrimaryEntries.length,
    actionableCount: effectivePrimaryEntries.filter((finding) => finding.status !== 'not_confirmed').length,
    hiddenNotConfirmedCount: countsByStatus.not_confirmed,
    countsByStatus,
    latestFindingAt,
  };
};

export const upsertFocusedScanVerdictSummary = (summary: FocusedScanVerdictSummary) => {
  db.prepare(`
    INSERT INTO focused_scan_verdict_summaries (
      scan_id,
      objective_id,
      overall_verdict,
      total_cases,
      counts_by_verdict_json,
      manual_review_recommended,
      major_blockers_json,
      latest_verdict_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(scan_id) DO UPDATE SET
      objective_id = excluded.objective_id,
      overall_verdict = excluded.overall_verdict,
      total_cases = excluded.total_cases,
      counts_by_verdict_json = excluded.counts_by_verdict_json,
      manual_review_recommended = excluded.manual_review_recommended,
      major_blockers_json = excluded.major_blockers_json,
      latest_verdict_at = excluded.latest_verdict_at,
      updated_at = CURRENT_TIMESTAMP
  `).run(
    summary.scanId,
    summary.objectiveId,
    summary.overallVerdict,
    summary.totalCases,
    JSON.stringify(summary.countsByVerdict),
    summary.manualReviewRecommended ? 1 : 0,
    JSON.stringify(summary.majorBlockers || []),
    summary.latestVerdictAt ?? null,
  );

  return getFocusedScanVerdictSummary(summary.scanId);
};

export const getFocusedScanVerdictSummary = (scanId: string): FocusedScanVerdictSummary | null => {
  const row = db.prepare(`
    SELECT *
    FROM focused_scan_verdict_summaries
    WHERE scan_id = ?
  `).get(scanId) as any;

  return row ? mapFocusedScanVerdictSummaryRow(row) : null;
};

export const createFocusedInvestigationIssue = (issue: FocusedInvestigationIssue) => {
  return db.prepare(`
    INSERT INTO focused_test_case_investigation_issues (
      id,
      scan_id,
      case_id,
      execution_id,
      objective_id,
      issue_type,
      issue_title,
      issue_details,
      issue_status,
      impact,
      source,
      correlation_json,
      linked_evidence_ids_json,
      linked_verdict_ids_json,
      workaround_attempts_json,
      expert_followup_hint,
      assistance_summary,
      assistance_profile_key,
      assistance_provider,
      assistance_model,
      detected_at,
      resolved_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), ?)
  `).run(
    issue.id,
    issue.scanId,
    issue.caseId,
    issue.executionId,
    issue.objectiveId,
    issue.issueType,
    issue.issueTitle,
    issue.issueDetails ?? null,
    issue.issueStatus,
    issue.impact,
    issue.source || 'system',
    issue.correlation ? JSON.stringify(issue.correlation) : null,
    JSON.stringify(issue.linkedEvidenceIds || []),
    JSON.stringify(issue.linkedVerdictIds || []),
    JSON.stringify(issue.workaroundAttempts || []),
    issue.expertFollowupHint ?? null,
    issue.assistanceSummary ?? null,
    issue.assistanceProfileKey ?? null,
    issue.assistanceProvider ?? null,
    issue.assistanceModel ?? null,
    issue.detectedAt ?? null,
    issue.resolvedAt ?? null,
  );
};

export const getFocusedInvestigationIssueById = (scanId: string, caseId: string, issueId: string): FocusedInvestigationIssue | null => {
  const row = db.prepare(`
    SELECT *
    FROM focused_test_case_investigation_issues
    WHERE scan_id = ? AND case_id = ? AND id = ?
  `).get(scanId, caseId, issueId) as any;

  return row ? mapFocusedInvestigationIssueRow(row) : null;
};

export const updateFocusedInvestigationIssue = (
  scanId: string,
  caseId: string,
  issueId: string,
  updates: Partial<FocusedInvestigationIssue>,
): FocusedInvestigationIssue | null => {
  const assignments: string[] = [];
  const values: any[] = [];

  if (updates.issueTitle !== undefined) {
    assignments.push('issue_title = ?');
    values.push(updates.issueTitle);
  }
  if (updates.issueDetails !== undefined) {
    assignments.push('issue_details = ?');
    values.push(updates.issueDetails ?? null);
  }
  if (updates.issueStatus !== undefined) {
    assignments.push('issue_status = ?');
    values.push(normalizeFocusedInvestigationIssueStatus(updates.issueStatus));
  }
  if (updates.impact !== undefined) {
    assignments.push('impact = ?');
    values.push(normalizeFocusedInvestigationImpact(updates.impact));
  }
  if (updates.source !== undefined) {
    assignments.push('source = ?');
    values.push(updates.source);
  }
  if (updates.correlation !== undefined) {
    assignments.push('correlation_json = ?');
    values.push(updates.correlation ? JSON.stringify(updates.correlation) : null);
  }
  if (updates.linkedEvidenceIds !== undefined) {
    assignments.push('linked_evidence_ids_json = ?');
    values.push(JSON.stringify(updates.linkedEvidenceIds || []));
  }
  if (updates.linkedVerdictIds !== undefined) {
    assignments.push('linked_verdict_ids_json = ?');
    values.push(JSON.stringify(updates.linkedVerdictIds || []));
  }
  if (updates.workaroundAttempts !== undefined) {
    assignments.push('workaround_attempts_json = ?');
    values.push(JSON.stringify(updates.workaroundAttempts || []));
  }
  if (updates.expertFollowupHint !== undefined) {
    assignments.push('expert_followup_hint = ?');
    values.push(updates.expertFollowupHint ?? null);
  }
  if (updates.assistanceSummary !== undefined) {
    assignments.push('assistance_summary = ?');
    values.push(updates.assistanceSummary ?? null);
  }
  if (updates.assistanceProfileKey !== undefined) {
    assignments.push('assistance_profile_key = ?');
    values.push(updates.assistanceProfileKey ?? null);
  }
  if (updates.assistanceProvider !== undefined) {
    assignments.push('assistance_provider = ?');
    values.push(updates.assistanceProvider ?? null);
  }
  if (updates.assistanceModel !== undefined) {
    assignments.push('assistance_model = ?');
    values.push(updates.assistanceModel ?? null);
  }
  if (updates.detectedAt !== undefined) {
    assignments.push('detected_at = ?');
    values.push(updates.detectedAt ?? null);
  }
  if (updates.resolvedAt !== undefined) {
    assignments.push('resolved_at = ?');
    values.push(updates.resolvedAt ?? null);
  }

  if (assignments.length === 0) {
    return getFocusedInvestigationIssueById(scanId, caseId, issueId);
  }

  assignments.push('updated_at = CURRENT_TIMESTAMP');
  db.prepare(`
    UPDATE focused_test_case_investigation_issues
    SET ${assignments.join(', ')}
    WHERE scan_id = ? AND case_id = ? AND id = ?
  `).run(...values, scanId, caseId, issueId);

  return getFocusedInvestigationIssueById(scanId, caseId, issueId);
};

export const listFocusedInvestigationIssuesByExecution = (scanId: string, caseId: string, executionId: string): FocusedInvestigationIssue[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_investigation_issues
    WHERE scan_id = ? AND case_id = ? AND execution_id = ?
    ORDER BY COALESCE(detected_at, created_at) DESC, created_at DESC, id DESC
  `).all(scanId, caseId, executionId) as any[];

  return rows.map(mapFocusedInvestigationIssueRow);
};

export const listFocusedInvestigationIssuesByCase = (scanId: string, caseId: string): FocusedInvestigationIssue[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_investigation_issues
    WHERE scan_id = ? AND case_id = ?
    ORDER BY COALESCE(detected_at, created_at) DESC, created_at DESC, id DESC
  `).all(scanId, caseId) as any[];

  return rows.map(mapFocusedInvestigationIssueRow);
};

export const listFocusedInvestigationIssuesByScan = (scanId: string): FocusedInvestigationIssue[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_investigation_issues
    WHERE scan_id = ?
    ORDER BY COALESCE(detected_at, created_at) DESC, created_at DESC, id DESC
  `).all(scanId) as any[];

  return rows.map(mapFocusedInvestigationIssueRow);
};

function summarizeFocusedCaseInvestigationIssues(caseId: string, issues: FocusedInvestigationIssue[]): FocusedCaseInvestigationSummary {
  if (issues.length === 0) {
    return {
      caseId,
      totalIssues: 0,
      unresolvedCount: 0,
      blockingCount: 0,
      degradingCount: 0,
      latestDetectedAt: null,
      latestIssueType: null,
      latestIssueTitle: null,
      latestIssueStatus: null,
      latestImpact: null,
      latestExpertFollowupHint: null,
      latestAssistanceSummary: null,
    };
  }

  const latestIssue = [...issues].sort((left, right) => {
    const leftTs = left.detectedAt || left.createdAt || '';
    const rightTs = right.detectedAt || right.createdAt || '';
    return rightTs.localeCompare(leftTs);
  })[0];
  const unresolvedIssues = issues
    .filter((issue) => isFocusedInvestigationIssueUnresolved(issue.issueStatus))
    .sort((left, right) => {
      const leftTs = left.detectedAt || left.createdAt || '';
      const rightTs = right.detectedAt || right.createdAt || '';
      return rightTs.localeCompare(leftTs);
    });
  const latestRelevantIssue = unresolvedIssues[0] || latestIssue;

  return {
    caseId,
    totalIssues: issues.length,
    unresolvedCount: unresolvedIssues.length,
    blockingCount: unresolvedIssues.filter((issue) => issue.impact === 'blocking').length,
    degradingCount: unresolvedIssues.filter((issue) => issue.impact === 'degrading').length,
    latestDetectedAt: latestIssue.detectedAt || latestIssue.createdAt || null,
    latestIssueType: latestRelevantIssue?.issueType || null,
    latestIssueTitle: latestRelevantIssue?.issueTitle || null,
    latestIssueStatus: latestRelevantIssue?.issueStatus || null,
    latestImpact: latestRelevantIssue?.impact || null,
    latestExpertFollowupHint: latestRelevantIssue?.expertFollowupHint || null,
    latestAssistanceSummary: latestRelevantIssue?.assistanceSummary || null,
  };
}

export const getFocusedCaseInvestigationSummaryByCase = (scanId: string, caseId: string): FocusedCaseInvestigationSummary | null => {
  const issues = listFocusedInvestigationIssuesByCase(scanId, caseId);
  return issues.length > 0 ? summarizeFocusedCaseInvestigationIssues(caseId, issues) : null;
};

export const listFocusedCaseInvestigationSummariesByScan = (scanId: string): FocusedCaseInvestigationSummary[] => {
  const grouped = new Map<string, FocusedInvestigationIssue[]>();

  for (const issue of listFocusedInvestigationIssuesByScan(scanId)) {
    const bucket = grouped.get(issue.caseId) || [];
    bucket.push(issue);
    grouped.set(issue.caseId, bucket);
  }

  return [...grouped.entries()].map(([caseId, issues]) => summarizeFocusedCaseInvestigationIssues(caseId, issues));
};

export const upsertFocusedScanBlockerSummary = (summary: FocusedScanBlockerSummary) => {
  db.prepare(`
    INSERT INTO focused_scan_blocker_summaries (
      scan_id,
      objective_id,
      counts_by_status_json,
      counts_by_impact_json,
      unresolved_by_type_json,
      repeated_blockers_json,
      cases_needing_review_json,
      latest_major_blocker_summary
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(scan_id) DO UPDATE SET
      objective_id = excluded.objective_id,
      counts_by_status_json = excluded.counts_by_status_json,
      counts_by_impact_json = excluded.counts_by_impact_json,
      unresolved_by_type_json = excluded.unresolved_by_type_json,
      repeated_blockers_json = excluded.repeated_blockers_json,
      cases_needing_review_json = excluded.cases_needing_review_json,
      latest_major_blocker_summary = excluded.latest_major_blocker_summary,
      updated_at = CURRENT_TIMESTAMP
  `).run(
    summary.scanId,
    summary.objectiveId,
    JSON.stringify(summary.countsByStatus || createEmptyFocusedInvestigationStatusCounts()),
    JSON.stringify(summary.countsByImpact || createEmptyFocusedInvestigationImpactCounts()),
    JSON.stringify(summary.unresolvedByType || createEmptyFocusedInvestigationTypeCounts()),
    JSON.stringify(summary.repeatedBlockers || []),
    JSON.stringify(summary.casesNeedingReview || []),
    summary.latestMajorBlockerSummary ?? null,
  );

  return getFocusedScanBlockerSummary(summary.scanId);
};

export const getFocusedScanBlockerSummary = (scanId: string): FocusedScanBlockerSummary | null => {
  const row = db.prepare(`
    SELECT *
    FROM focused_scan_blocker_summaries
    WHERE scan_id = ?
  `).get(scanId) as any;

  return row ? mapFocusedScanBlockerSummaryRow(row) : null;
};

export const upsertFocusedHistoricalCompareState = (state: FocusedHistoricalCompareState) => {
  db.prepare(`
    INSERT INTO focused_scan_historical_compare_states (
      scan_id,
      scope_type,
      target_origin,
      scope_identity_key,
      comparison_status,
      baseline_scan_id,
      compared_against_scan_id,
      first_observed_at,
      latest_compare_at,
      status_reason,
      assistance_profile_key,
      assistance_provider,
      assistance_model,
      assistance_narrative
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(scan_id) DO UPDATE SET
      scope_type = excluded.scope_type,
      target_origin = excluded.target_origin,
      scope_identity_key = excluded.scope_identity_key,
      comparison_status = excluded.comparison_status,
      baseline_scan_id = excluded.baseline_scan_id,
      compared_against_scan_id = excluded.compared_against_scan_id,
      first_observed_at = excluded.first_observed_at,
      latest_compare_at = excluded.latest_compare_at,
      status_reason = excluded.status_reason,
      assistance_profile_key = excluded.assistance_profile_key,
      assistance_provider = excluded.assistance_provider,
      assistance_model = excluded.assistance_model,
      assistance_narrative = excluded.assistance_narrative,
      updated_at = CURRENT_TIMESTAMP
  `).run(
    state.scanId,
    state.scopeType,
    state.targetOrigin,
    state.scopeIdentityKey,
    state.comparisonStatus,
    state.baselineScanId ?? null,
    state.comparedAgainstScanId ?? null,
    state.firstObservedAt ?? null,
    state.latestCompareAt ?? null,
    state.statusReason ?? null,
    state.assistanceProfileKey ?? null,
    state.assistanceProvider ?? null,
    state.assistanceModel ?? null,
    state.assistanceNarrative ?? null,
  );

  return getFocusedHistoricalCompareState(state.scanId);
};

export const getFocusedHistoricalCompareState = (scanId: string): FocusedHistoricalCompareState | null => {
  const row = db.prepare(`
    SELECT *
    FROM focused_scan_historical_compare_states
    WHERE scan_id = ?
  `).get(scanId) as any;

  return row ? mapFocusedHistoricalCompareStateRow(row) : null;
};

export const listFocusedHistoricalCompareStatesByLineage = (scopeIdentityKey: string): FocusedHistoricalCompareState[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_scan_historical_compare_states
    WHERE scope_identity_key = ?
    ORDER BY COALESCE(first_observed_at, created_at) ASC, created_at ASC, scan_id ASC
  `).all(scopeIdentityKey) as any[];

  return rows.map(mapFocusedHistoricalCompareStateRow);
};

export const upsertFocusedCaseHistoricalCompare = (compare: FocusedCaseHistoricalCompare) => {
  db.prepare(`
    INSERT INTO focused_test_case_historical_compares (
      id,
      current_scan_id,
      current_case_id,
      current_execution_id,
      case_identity_key,
      case_variant_key,
      previous_scan_id,
      previous_case_id,
      previous_execution_id,
      compare_status,
      historical_outcome,
      prior_verdict,
      current_verdict,
      verdict_transition,
      prior_evidence_sufficiency,
      current_evidence_sufficiency,
      prior_verdict_reason,
      current_verdict_reason,
      prior_evidence_summary,
      current_evidence_summary,
      evidence_drift_classification,
      blocker_recurrence_json,
      compare_narrative,
      assistance_profile_key,
      assistance_provider,
      assistance_model,
      latest_compare_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(current_scan_id, current_case_id) DO UPDATE SET
      current_execution_id = excluded.current_execution_id,
      case_identity_key = excluded.case_identity_key,
      case_variant_key = excluded.case_variant_key,
      previous_scan_id = excluded.previous_scan_id,
      previous_case_id = excluded.previous_case_id,
      previous_execution_id = excluded.previous_execution_id,
      compare_status = excluded.compare_status,
      historical_outcome = excluded.historical_outcome,
      prior_verdict = excluded.prior_verdict,
      current_verdict = excluded.current_verdict,
      verdict_transition = excluded.verdict_transition,
      prior_evidence_sufficiency = excluded.prior_evidence_sufficiency,
      current_evidence_sufficiency = excluded.current_evidence_sufficiency,
      prior_verdict_reason = excluded.prior_verdict_reason,
      current_verdict_reason = excluded.current_verdict_reason,
      prior_evidence_summary = excluded.prior_evidence_summary,
      current_evidence_summary = excluded.current_evidence_summary,
      evidence_drift_classification = excluded.evidence_drift_classification,
      blocker_recurrence_json = excluded.blocker_recurrence_json,
      compare_narrative = excluded.compare_narrative,
      assistance_profile_key = excluded.assistance_profile_key,
      assistance_provider = excluded.assistance_provider,
      assistance_model = excluded.assistance_model,
      latest_compare_at = excluded.latest_compare_at,
      updated_at = CURRENT_TIMESTAMP
  `).run(
    compare.id,
    compare.currentScanId,
    compare.currentCaseId,
    compare.currentExecutionId ?? null,
    compare.caseIdentityKey,
    compare.caseVariantKey,
    compare.previousScanId ?? null,
    compare.previousCaseId ?? null,
    compare.previousExecutionId ?? null,
    compare.compareStatus,
    compare.historicalOutcome ?? null,
    compare.priorVerdict ?? null,
    compare.currentVerdict ?? null,
    compare.verdictTransition ?? null,
    compare.priorEvidenceSufficiency ?? null,
    compare.currentEvidenceSufficiency ?? null,
    compare.priorVerdictReason ?? null,
    compare.currentVerdictReason ?? null,
    compare.priorEvidenceSummary ?? null,
    compare.currentEvidenceSummary ?? null,
    compare.evidenceDriftClassification ?? null,
    JSON.stringify(compare.blockerRecurrence || createEmptyFocusedBlockerRecurrenceSummary()),
    compare.compareNarrative ?? null,
    compare.assistanceProfileKey ?? null,
    compare.assistanceProvider ?? null,
    compare.assistanceModel ?? null,
    compare.latestCompareAt ?? null,
  );

  return getFocusedCaseHistoricalCompareByCase(compare.currentScanId, compare.currentCaseId);
};

export const getFocusedCaseHistoricalCompareByCase = (scanId: string, caseId: string): FocusedCaseHistoricalCompare | null => {
  const row = db.prepare(`
    SELECT *
    FROM focused_test_case_historical_compares
    WHERE current_scan_id = ? AND current_case_id = ?
  `).get(scanId, caseId) as any;

  return row ? mapFocusedCaseHistoricalCompareRow(row) : null;
};

export const listFocusedCaseHistoricalComparesByScan = (scanId: string): FocusedCaseHistoricalCompare[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_historical_compares
    WHERE current_scan_id = ?
    ORDER BY created_at ASC, id ASC
  `).all(scanId) as any[];

  return rows.map(mapFocusedCaseHistoricalCompareRow);
};

export const upsertFocusedHistoricalCompareSummary = (summary: FocusedHistoricalCompareSummary) => {
  db.prepare(`
    INSERT INTO focused_scan_historical_compare_summaries (
      scan_id,
      baseline_scan_id,
      compared_against_scan_id,
      comparison_status,
      overall_change_classification,
      counts_by_verdict_transition_json,
      improved_count,
      regressed_count,
      unchanged_count,
      weaker_confidence_count,
      stronger_confidence_count,
      newly_introduced_count,
      not_comparable_count,
      removed_prior_case_count,
      improved_cases_json,
      regressed_cases_json,
      unstable_cases_json,
      repeated_blocker_families_json,
      new_blocker_families_json,
      resolved_blocker_families_json,
      removed_prior_cases_json,
      stability_notes_json,
      manual_review_recommended,
      latest_compare_at,
      assistance_profile_key,
      assistance_provider,
      assistance_model,
      compare_narrative
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(scan_id) DO UPDATE SET
      baseline_scan_id = excluded.baseline_scan_id,
      compared_against_scan_id = excluded.compared_against_scan_id,
      comparison_status = excluded.comparison_status,
      overall_change_classification = excluded.overall_change_classification,
      counts_by_verdict_transition_json = excluded.counts_by_verdict_transition_json,
      improved_count = excluded.improved_count,
      regressed_count = excluded.regressed_count,
      unchanged_count = excluded.unchanged_count,
      weaker_confidence_count = excluded.weaker_confidence_count,
      stronger_confidence_count = excluded.stronger_confidence_count,
      newly_introduced_count = excluded.newly_introduced_count,
      not_comparable_count = excluded.not_comparable_count,
      removed_prior_case_count = excluded.removed_prior_case_count,
      improved_cases_json = excluded.improved_cases_json,
      regressed_cases_json = excluded.regressed_cases_json,
      unstable_cases_json = excluded.unstable_cases_json,
      repeated_blocker_families_json = excluded.repeated_blocker_families_json,
      new_blocker_families_json = excluded.new_blocker_families_json,
      resolved_blocker_families_json = excluded.resolved_blocker_families_json,
      removed_prior_cases_json = excluded.removed_prior_cases_json,
      stability_notes_json = excluded.stability_notes_json,
      manual_review_recommended = excluded.manual_review_recommended,
      latest_compare_at = excluded.latest_compare_at,
      assistance_profile_key = excluded.assistance_profile_key,
      assistance_provider = excluded.assistance_provider,
      assistance_model = excluded.assistance_model,
      compare_narrative = excluded.compare_narrative,
      updated_at = CURRENT_TIMESTAMP
  `).run(
    summary.scanId,
    summary.baselineScanId ?? null,
    summary.comparedAgainstScanId ?? null,
    summary.comparisonStatus,
    summary.overallChangeClassification,
    JSON.stringify(summary.countsByVerdictTransition || createEmptyFocusedVerdictTransitionCounts()),
    summary.improvedCount,
    summary.regressedCount,
    summary.unchangedCount,
    summary.weakerConfidenceCount,
    summary.strongerConfidenceCount,
    summary.newlyIntroducedCount,
    summary.notComparableCount,
    summary.removedPriorCaseCount,
    JSON.stringify(summary.improvedCases || []),
    JSON.stringify(summary.regressedCases || []),
    JSON.stringify(summary.unstableCases || []),
    JSON.stringify(summary.repeatedBlockerFamilies || []),
    JSON.stringify(summary.newBlockerFamilies || []),
    JSON.stringify(summary.resolvedBlockerFamilies || []),
    JSON.stringify(summary.removedPriorCases || []),
    JSON.stringify(summary.stabilityNotes || []),
    summary.manualReviewRecommended ? 1 : 0,
    summary.latestCompareAt ?? null,
    summary.assistanceProfileKey ?? null,
    summary.assistanceProvider ?? null,
    summary.assistanceModel ?? null,
    summary.compareNarrative ?? null,
  );

  return getFocusedHistoricalCompareSummary(summary.scanId);
};

export const getFocusedHistoricalCompareSummary = (scanId: string): FocusedHistoricalCompareSummary | null => {
  const row = db.prepare(`
    SELECT *
    FROM focused_scan_historical_compare_summaries
    WHERE scan_id = ?
  `).get(scanId) as any;

  return row ? mapFocusedHistoricalCompareSummaryRow(row) : null;
};

export const deleteFocusedHistoricalCompareArtifactsByScan = (scanId: string) => {
  return db.transaction(() => {
    db.prepare('DELETE FROM focused_test_case_historical_compares WHERE current_scan_id = ?').run(scanId);
    db.prepare('DELETE FROM focused_scan_historical_compare_summaries WHERE scan_id = ?').run(scanId);
    db.prepare('DELETE FROM focused_scan_historical_compare_states WHERE scan_id = ?').run(scanId);
  })();
};

function listFocusedExecutionTracePreviewByExecutionIds(
  scanId: string,
  executionIds: string[],
  limitPerExecution = 3,
): Map<string, FocusedExecutionTraceEntry[]> {
  const previews = new Map<string, FocusedExecutionTraceEntry[]>();
  if (executionIds.length === 0) {
    return previews;
  }

  const placeholders = executionIds.map(() => '?').join(', ');
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_case_execution_trace_entries
    WHERE scan_id = ? AND execution_id IN (${placeholders})
    ORDER BY execution_id ASC, timestamp DESC, created_at DESC, id DESC
  `).all(scanId, ...executionIds) as any[];

  for (const row of rows) {
    const entry = mapFocusedExecutionTraceEntryRow(row);
    const existing = previews.get(entry.executionId) || [];
    if (existing.length >= limitPerExecution) {
      continue;
    }
    existing.push(entry);
    previews.set(entry.executionId, existing);
  }

  for (const [executionId, entries] of previews.entries()) {
    previews.set(executionId, [...entries].reverse());
  }

  return previews;
}

export const listFocusedExecutionSummariesByScan = (scanId: string): FocusedExecutionSummary[] => {
  const rows = db.prepare(`
    SELECT
      latest.case_id,
      latest.id AS execution_id,
      latest.execution_state,
      latest.execution_profile_key,
      latest.notes_summary,
      latest.error_message,
      latest.request_actions_used,
      latest.started_at,
      latest.completed_at,
      latest.browser_actions_used,
      latest.browser_session_id,
      COALESCE(evidence_counts.evidence_count, 0) AS evidence_count,
      COALESCE(evidence_counts.browser_evidence_count, 0) AS browser_evidence_count,
      COALESCE(evidence_counts.scope_violation_count, 0) AS scope_violation_count
    FROM focused_test_case_executions latest
    INNER JOIN (
      SELECT case_id, MAX(COALESCE(started_at, created_at)) AS latest_started_at
      FROM focused_test_case_executions
      WHERE scan_id = ?
      GROUP BY case_id
    ) latest_keys
      ON latest.case_id = latest_keys.case_id
     AND COALESCE(latest.started_at, latest.created_at) = latest_keys.latest_started_at
    LEFT JOIN (
      SELECT
        execution_id,
        COUNT(*) AS evidence_count,
        SUM(CASE WHEN source IN ('browser_flow', 'browser_verification') THEN 1 ELSE 0 END) AS browser_evidence_count,
        SUM(CASE WHEN scope_violation_json IS NOT NULL AND scope_violation_json != '' THEN 1 ELSE 0 END) AS scope_violation_count
      FROM focused_test_case_evidence_bundles
      WHERE scan_id = ?
      GROUP BY execution_id
    ) evidence_counts
      ON latest.id = evidence_counts.execution_id
    WHERE latest.scan_id = ?
    ORDER BY latest.created_at DESC, latest.id DESC
  `).all(scanId, scanId, scanId) as any[];

  const previewMap = listFocusedExecutionTracePreviewByExecutionIds(
    scanId,
    rows.map((row) => row.execution_id).filter((value): value is string => typeof value === 'string' && value.length > 0),
  );

  const deduped = new Map<string, FocusedExecutionSummary>();
  for (const row of rows) {
    if (deduped.has(row.case_id)) {
      continue;
    }
    const latestTracePreview = previewMap.get(row.execution_id) || [];
    deduped.set(row.case_id, {
      caseId: row.case_id,
      executionState: normalizeFocusedExecutionState(row.execution_state),
      executionPresentationState: normalizeFocusedExecutionPresentationState(deriveFocusedExecutionPresentationState({
        status: 'planned',
        reviewState: 'approved',
        executionState: normalizeFocusedExecutionState(row.execution_state),
        lastExecutionId: row.execution_id ?? null,
        evidenceCount: Number(row.evidence_count) || 0,
      })),
      lastRunAt: row.started_at ?? null,
      lastCompletedAt: row.completed_at ?? null,
      lastExecutionId: row.execution_id ?? null,
      executionNotesSummary: row.notes_summary ?? null,
      executionError: row.error_message ?? null,
      evidenceCount: Number(row.evidence_count) || 0,
      browserEvidenceCount: Number(row.browser_evidence_count) || 0,
      scopeViolationCount: Number(row.scope_violation_count) || 0,
      browserActionsUsed: Number(row.browser_actions_used) || 0,
      executionProfileKey: row.execution_profile_key ?? null,
      browserSessionId: row.browser_session_id ?? null,
      executionRailSummary: buildFocusedRailUsageSummary({
        requestActionsUsed: Number(row.request_actions_used) || 0,
        browserActionsUsed: Number(row.browser_actions_used) || 0,
        traceCount: latestTracePreview.length,
      }),
      latestTracePreview,
    });
  }

  return [...deduped.values()];
};

export const getFocusedExecutionSummaryByCase = (scanId: string, caseId: string): FocusedExecutionSummary | null => {
  const summaries = listFocusedExecutionSummariesByScan(scanId);
  return summaries.find((entry) => entry.caseId === caseId) || null;
};

export const listFocusedTestCasesWithExecutionSummary = (scanId: string): FocusedTestCase[] => {
  const cases = listFocusedTestCasesByScan(scanId);
  const summaryMap = new Map(listFocusedExecutionSummariesByScan(scanId).map((summary) => [summary.caseId, summary]));
  const verdictMap = new Map(listLatestFocusedCaseVerdictsByScan(scanId).map((verdict) => [verdict.caseId, verdict]));
  const findingMap = new Map<string, FocusedCaseFinding[]>();
  for (const finding of listLatestFocusedCaseFindingsByScan(scanId)) {
    const existing = findingMap.get(finding.caseId) || [];
    existing.push(finding);
    findingMap.set(finding.caseId, existing);
  }
  const findingThreadMap = new Map<string, FocusedFindingThread[]>();
  for (const thread of listLatestFocusedFindingThreadsByScan(scanId)) {
    const existing = findingThreadMap.get(thread.caseId) || [];
    existing.push(thread);
    findingThreadMap.set(thread.caseId, existing);
  }
  const investigationSummaryMap = new Map(listFocusedCaseInvestigationSummariesByScan(scanId).map((summary) => [summary.caseId, summary]));
  const compareMap = new Map(listFocusedCaseHistoricalComparesByScan(scanId).map((compare) => [compare.currentCaseId, compare]));
  return cases.map((testCase) => {
    const summary = summaryMap.get(testCase.id);
    const verdict = verdictMap.get(testCase.id);
    const findings = findingMap.get(testCase.id) || [];
    const findingThreads = findingThreadMap.get(testCase.id) || [];
    const investigationSummary = investigationSummaryMap.get(testCase.id);
    const historicalCompare = compareMap.get(testCase.id);
    const matchingVerdict = !summary?.lastExecutionId || verdict?.executionId === summary.lastExecutionId
      ? verdict
      : null;

    return applyFocusedHistoricalCompare(
      applyFocusedInvestigationSummary(
        applyFocusedCaseFindings(
          applyFocusedFindingThreads(
            applyFocusedCaseVerdict(
              applyFocusedExecutionSummary(testCase, summary),
              matchingVerdict,
            ),
            summary?.lastExecutionId
              ? findingThreads.filter((entry) => entry.executionId === summary.lastExecutionId)
              : findingThreads,
          ),
          summary?.lastExecutionId
            ? findings.filter((entry) => entry.executionId === summary.lastExecutionId)
            : findings,
        ),
        investigationSummary,
      ),
      historicalCompare,
    );
  });
};

export const createFocusedTestCase = (testCase: FocusedTestCase) => {
  return db.prepare(`
    INSERT INTO focused_test_cases (
      id,
      scan_id,
      objective_id,
      title,
      hypothesis,
      target_artifact_json,
      preconditions_json,
      steps_json,
      assertions_json,
      required_evidence_json,
      priority,
      planner_rationale_summary,
      case_family,
      case_intelligence_json,
      max_adaptive_follow_ups,
      preferred_rail,
      allowed_confirmation_kinds_json,
      status,
      review_state
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    testCase.id,
    testCase.scanId,
    testCase.objectiveId,
    testCase.title,
    testCase.hypothesis,
    JSON.stringify(testCase.targetArtifact || {}),
    JSON.stringify(testCase.preconditions || []),
    JSON.stringify(testCase.steps || []),
    JSON.stringify(testCase.assertions || []),
    JSON.stringify(testCase.requiredEvidence || []),
    testCase.priority,
    testCase.plannerRationaleSummary,
    normalizeFocusedCaseFamily(testCase.caseFamily),
    JSON.stringify(testCase.caseIntelligence || {}),
    Math.max(0, Number(testCase.maxAdaptiveFollowUps) || 0),
    normalizeFocusedExecutionRail(testCase.preferredRail),
    JSON.stringify(testCase.allowedConfirmationKinds || []),
    testCase.status,
    testCase.reviewState,
  );
};

export const listFocusedTestCasesByScan = (scanId: string): FocusedTestCase[] => {
  const rows = db.prepare(`
    SELECT *
    FROM focused_test_cases
    WHERE scan_id = ?
    ORDER BY
      CASE priority
        WHEN 'high' THEN 0
        WHEN 'medium' THEN 1
        ELSE 2
      END,
      created_at ASC,
      id ASC
  `).all(scanId) as any[];

  return rows.map(mapFocusedTestCaseRow);
};

export const getFocusedTestCaseById = (scanId: string, caseId: string): FocusedTestCase | null => {
  const row = db.prepare('SELECT * FROM focused_test_cases WHERE scan_id = ? AND id = ?').get(scanId, caseId) as any;
  return row ? mapFocusedTestCaseRow(row) : null;
};

export const deleteFocusedTestCasesByScan = (scanId: string) => {
  return db.transaction(() => {
    deleteFocusedHistoricalCompareArtifactsByScan(scanId);
    db.prepare('DELETE FROM focused_scan_blocker_summaries WHERE scan_id = ?').run(scanId);
    db.prepare('DELETE FROM focused_scan_verdict_summaries WHERE scan_id = ?').run(scanId);
    return db.prepare('DELETE FROM focused_test_cases WHERE scan_id = ?').run(scanId);
  })();
};

export const replaceFocusedTestCasesByScan = (scanId: string, testCases: FocusedTestCase[]) => {
  return db.transaction(() => {
    deleteFocusedTestCasesByScan(scanId);
    for (const testCase of testCases) {
      createFocusedTestCase(testCase);
    }
  })();
};

export const updateFocusedTestCase = (scanId: string, caseId: string, updates: {
  priority?: string;
  status?: string;
  reviewState?: string;
}) => {
  const assignments: string[] = [];
  const values: any[] = [];

  if (updates.priority !== undefined) {
    assignments.push('priority = ?');
    values.push(updates.priority);
  }
  if (updates.status !== undefined) {
    assignments.push('status = ?');
    values.push(updates.status);
  }
  if (updates.reviewState !== undefined) {
    assignments.push('review_state = ?');
    values.push(updates.reviewState);
  }

  if (assignments.length === 0) {
    return getFocusedTestCaseById(scanId, caseId);
  }

  assignments.push('updated_at = CURRENT_TIMESTAMP');
  db.prepare(`
    UPDATE focused_test_cases
    SET ${assignments.join(', ')}
    WHERE scan_id = ? AND id = ?
  `).run(...values, scanId, caseId);

  return getFocusedTestCaseById(scanId, caseId);
};

export const getReportSnapshotByFingerprint = (scanId: string, fingerprint: string) => {
  return db.prepare('SELECT * FROM report_snapshots WHERE scan_id = ? AND fingerprint = ?').get(scanId, fingerprint) as any;
};

export const getReportSnapshot = (snapshotId: string) => {
  return db.prepare('SELECT * FROM report_snapshots WHERE id = ?').get(snapshotId) as any;
};

export const upsertReportSnapshot = (data: {
  id: string;
  scanId: string;
  fingerprint: string;
  reportJson: string;
}) => {
  const existing = getReportSnapshotByFingerprint(data.scanId, data.fingerprint);
  if (existing) {
    db.prepare(`
      UPDATE report_snapshots
      SET report_json = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(data.reportJson, existing.id);
    return getReportSnapshot(existing.id);
  }

  db.prepare(`
    INSERT INTO report_snapshots (id, scan_id, fingerprint, report_json)
    VALUES (?, ?, ?, ?)
  `).run(data.id, data.scanId, data.fingerprint, data.reportJson);
  return getReportSnapshot(data.id);
};

export const listReportExportsByScan = (scanId: string) => {
  return db.prepare(`
    SELECT * FROM report_exports
    WHERE scan_id = ?
    ORDER BY created_at DESC
  `).all(scanId) as any[];
};

export const getReportExport = (exportId: string) => {
  return db.prepare('SELECT * FROM report_exports WHERE id = ?').get(exportId) as any;
};

export const createReportExport = (data: {
  id: string;
  scanId: string;
  snapshotId: string;
  snapshotFingerprint: string;
  format: 'pdf' | 'docx' | 'pptx';
  enrichmentMode: 'deterministic' | 'llm';
  llmStatus?: string;
}) => {
  db.prepare(`
    INSERT INTO report_exports (
      id, scan_id, snapshot_id, snapshot_fingerprint, format, enrichment_mode, status, stage, llm_status
    ) VALUES (?, ?, ?, ?, ?, ?, 'pending', 'queued', ?)
  `).run(
    data.id,
    data.scanId,
    data.snapshotId,
    data.snapshotFingerprint,
    data.format,
    data.enrichmentMode,
    data.llmStatus || (data.enrichmentMode === 'llm' ? 'queued' : 'skipped'),
  );
  return getReportExport(data.id);
};

export const updateReportExport = (exportId: string, updates: Record<string, any>) => {
  const normalized = { ...updates };
  delete normalized.id;
  if (Object.keys(normalized).length === 0) {
    return getReportExport(exportId);
  }

  normalized.updated_at = normalized.updated_at || new Date().toISOString();

  const setClauses = Object.keys(normalized).map((key) => `${key} = ?`).join(', ');
  const values = Object.values(normalized);
  db.prepare(`UPDATE report_exports SET ${setClauses} WHERE id = ?`).run(...values, exportId);
  return getReportExport(exportId);
};

export const getReusableReportExport = (data: {
  scanId: string;
  snapshotId: string;
  format: 'pdf' | 'docx' | 'pptx';
  enrichmentMode: 'deterministic' | 'llm';
}) => {
  return db.prepare(`
    SELECT *
    FROM report_exports
    WHERE scan_id = ?
      AND snapshot_id = ?
      AND format = ?
      AND enrichment_mode = ?
      AND status IN ('pending', 'running', 'completed')
    ORDER BY
      CASE status
        WHEN 'running' THEN 0
        WHEN 'pending' THEN 1
        WHEN 'completed' THEN 2
        ELSE 3
      END,
      created_at DESC
    LIMIT 1
  `).get(data.scanId, data.snapshotId, data.format, data.enrichmentMode) as any;
};

export const listRecoverableReportExports = () => {
  return db.prepare(`
    SELECT *
    FROM report_exports
    WHERE status IN ('pending', 'running')
      AND stage NOT IN ('completed', 'failed', 'canceled')
    ORDER BY created_at ASC
  `).all() as any[];
};

/** Permanently delete scans by id; only deletes rows where user_id matches (CASCADE removes related data). */
export const deleteScans = (scanIds: string[], userId: number) => {
  if (!scanIds.length) return { changes: 0 };
  const placeholders = scanIds.map(() => '?').join(',');
  return db.prepare(`DELETE FROM scans WHERE user_id = ? AND id IN (${placeholders})`).run(userId, ...scanIds);
};

export const getVulnerabilitiesByScan = (scanId: string) => {
  return db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId) as any[];
};

export const addVulnerability = (data: {
  scanId: string;
  name: string;
  description?: string;
  severity: string;
  cvssScore?: number;
  cvssVector?: string;
  cwe?: string;
  cve?: string;
  request?: string;
  response?: string;
  evidence?: string;
  remediation?: string;
  screenshotPath?: string;
}) => {
  // better-sqlite3 rejects undefined values — build explicit safe array
  const safeVal = (v: any, fallback: any = null) => (v === undefined || v === null) ? fallback : v;
  const values = [
    safeVal(data.scanId, 'unknown'),
    safeVal(data.name, 'Unknown Vulnerability'),
    safeVal(data.description),
    safeVal(data.severity, 'medium'),
    safeVal(data.cvssScore),
    safeVal(data.cvssVector),
    safeVal(data.cwe),
    safeVal(data.cve),
    safeVal(data.request),
    safeVal(data.response),
    safeVal(data.evidence),
    safeVal(data.remediation),
    safeVal(data.screenshotPath),
  ];
  return db.prepare(`
    INSERT INTO vulnerabilities (scan_id, name, description, severity, cvss_score, cvss_vector, cwe, cve, request, response, evidence, remediation, screenshot_path)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(...values);
};

// ── Scan Logs (persisted to DB) ──
// Lazy-initialized prepared statements (tables may not exist at module load time)

export const saveScanLogs = (scanId: string, logs: string[]) => {
  if (!logs || logs.length === 0) return;
  try {
    const stmt = db.prepare('INSERT INTO scan_logs (scan_id, message) VALUES (?, ?)');
    const insertMany = db.transaction((messages: string[]) => {
      for (const msg of messages) {
        stmt.run(scanId, msg);
      }
    });
    insertMany(logs);
  } catch (e: any) {
    logger.error(`Failed to save scan logs: ${e.message}`);
  }
};

export const getScanLogs = (scanId: string): string[] => {
  const rows = db.prepare('SELECT message FROM scan_logs WHERE scan_id = ? ORDER BY id ASC').all(scanId) as { message: string }[];
  return rows.map(r => r.message);
};

// ── Scan Chat Messages (persisted to DB) ──

export const saveChatMessage = (scanId: string, role: 'human' | 'assistant', content: string) => {
  try {
    db.prepare('INSERT INTO scan_chat_messages (scan_id, role, content) VALUES (?, ?, ?)').run(scanId, role, content);
  } catch (e: any) {
    logger.error(`Failed to save chat message: ${e.message}`);
  }
};

export const getChatMessages = (scanId: string): { role: string; content: string; created_at: string }[] => {
  return db.prepare('SELECT role, content, created_at FROM scan_chat_messages WHERE scan_id = ? ORDER BY id ASC').all(scanId) as any[];
};

// ── Report Analysis (Red Team Mind Reconstruction) ──

export const createAnalysis = (data: { id: string; userId: number; filename: string; filePath: string }) => {
  return db.prepare(`
    INSERT INTO report_analyses (id, user_id, filename, file_path, status)
    VALUES (?, ?, ?, ?, 'pending')
  `).run(data.id, data.userId, data.filename, data.filePath);
};

export const getAnalysis = (id: string) => {
  return db.prepare('SELECT * FROM report_analyses WHERE id = ?').get(id) as any;
};

export const getUserAnalyses = (userId: number) => {
  return db.prepare('SELECT * FROM report_analyses WHERE user_id = ? ORDER BY created_at DESC').all(userId) as any[];
};

export const updateAnalysisStatus = (id: string, status: string, errorMessage?: string) => {
  if (status === 'completed' || status === 'failed') {
    return db.prepare(`
      UPDATE report_analyses SET status = ?, completed_at = CURRENT_TIMESTAMP, error_message = ?
      WHERE id = ?
    `).run(status, errorMessage || null, id);
  }
  return db.prepare('UPDATE report_analyses SET status = ? WHERE id = ?').run(status, id);
};

export const updateAnalysisMetadata = (id: string, metadataJson: string) => {
  return db.prepare('UPDATE report_analyses SET report_metadata_json = ? WHERE id = ?').run(metadataJson, id);
};

export const updateAnalysisBehavioralProfile = (id: string, profileJson: string) => {
  return db.prepare('UPDATE report_analyses SET behavioral_profile_json = ? WHERE id = ?').run(profileJson, id);
};

export const addAnalysisFinding = (data: {
  analysisId: string;
  title: string;
  severity?: string;
  cvssScore?: number;
  cvssVector?: string;
  description?: string;
  pocStepsJson?: string;
  rawHttpRequestsJson?: string;
  payloadsJson?: string;
  evidenceJson?: string;
  recommendation?: string;
}) => {
  const safeVal = (v: any) => (v === undefined || v === null) ? null : v;
  return db.prepare(`
    INSERT INTO analysis_findings (analysis_id, title, severity, cvss_score, cvss_vector, description, poc_steps_json, raw_http_requests_json, payloads_json, evidence_json, recommendation)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    data.analysisId, data.title, safeVal(data.severity), safeVal(data.cvssScore), safeVal(data.cvssVector),
    safeVal(data.description), safeVal(data.pocStepsJson), safeVal(data.rawHttpRequestsJson),
    safeVal(data.payloadsJson), safeVal(data.evidenceJson), safeVal(data.recommendation)
  );
};

export const getAnalysisFindings = (analysisId: string) => {
  return db.prepare('SELECT * FROM analysis_findings WHERE analysis_id = ? ORDER BY id ASC').all(analysisId) as any[];
};

export const updateAnalysisFinding = (findingId: number, updates: Record<string, any>) => {
  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = Object.values(updates);
  return db.prepare(`UPDATE analysis_findings SET ${setClauses} WHERE id = ?`).run(...values, findingId);
};

export const saveAnalysisLog = (analysisId: string, message: string) => {
  try {
    db.prepare('INSERT INTO analysis_logs (analysis_id, message) VALUES (?, ?)').run(analysisId, message);
  } catch (e: any) {
    logger.error(`Failed to save analysis log: ${e.message}`);
  }
};

export const getAnalysisLogs = (analysisId: string): string[] => {
  const rows = db.prepare('SELECT message FROM analysis_logs WHERE analysis_id = ? ORDER BY id ASC').all(analysisId) as { message: string }[];
  return rows.map(r => r.message);
};

export const deleteAnalysis = (analysisId: string, userId: number) => {
  return db.prepare('DELETE FROM report_analyses WHERE id = ? AND user_id = ?').run(analysisId, userId);
};

// ── Mindset TTP Library ──

export const addTTP = (data: {
  id: string;
  sourceAnalysisId: string;
  sourceFindingId?: number;
  title: string;
  vulnerabilityClass: string;
  discoveryStrategyJson?: string;
  preconditionsJson?: string;
  entrypointHintsJson?: string;
  requestTemplatesJson?: string;
  payloadTemplatesJson?: string;
  verificationCriteriaJson?: string;
  confidence?: number;
  generalizationNotes?: string;
}) => {
  const safeVal = (v: any) => (v === undefined || v === null) ? null : v;
  return db.prepare(`
    INSERT INTO mindset_ttps (id, source_analysis_id, source_finding_id, title, vulnerability_class, discovery_strategy_json, preconditions_json, entrypoint_hints_json, request_templates_json, payload_templates_json, verification_criteria_json, confidence, generalization_notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    data.id, data.sourceAnalysisId, safeVal(data.sourceFindingId), data.title, data.vulnerabilityClass,
    safeVal(data.discoveryStrategyJson), safeVal(data.preconditionsJson), safeVal(data.entrypointHintsJson),
    safeVal(data.requestTemplatesJson), safeVal(data.payloadTemplatesJson), safeVal(data.verificationCriteriaJson),
    data.confidence ?? 0.5, safeVal(data.generalizationNotes)
  );
};

export const getAllTTPs = () => {
  return db.prepare('SELECT * FROM mindset_ttps ORDER BY created_at DESC').all() as any[];
};

export const getActiveTTPs = () => {
  return db.prepare('SELECT * FROM mindset_ttps WHERE is_active = 1 ORDER BY confidence DESC').all() as any[];
};

export const getTTPById = (id: string) => {
  return db.prepare('SELECT * FROM mindset_ttps WHERE id = ?').get(id) as any;
};

export const getTTPsByAnalysis = (analysisId: string) => {
  return db.prepare('SELECT * FROM mindset_ttps WHERE source_analysis_id = ? ORDER BY created_at ASC').all(analysisId) as any[];
};

export const toggleTTPActive = (id: string, isActive: boolean) => {
  return db.prepare('UPDATE mindset_ttps SET is_active = ? WHERE id = ?').run(isActive ? 1 : 0, id);
};

export const getMindsetProfile = () => {
  return db.prepare('SELECT * FROM mindset_profile ORDER BY updated_at DESC LIMIT 1').get() as any;
};

export const upsertMindsetProfile = (profileJson: string) => {
  const existing = getMindsetProfile();
  if (existing) {
    return db.prepare('UPDATE mindset_profile SET profile_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(profileJson, existing.id);
  }
  return db.prepare('INSERT INTO mindset_profile (profile_json) VALUES (?)').run(profileJson);
};

// ── Presence Scan Helpers ──

export const createPresenceScanRun = (data: {
  id: string; userId: number; ttpId: string; ttpTitle?: string; targetsCount: number;
}) => {
  return db.prepare(`
    INSERT INTO presence_scan_runs (id, user_id, ttp_id, ttp_title, targets_count, status, started_at)
    VALUES (?, ?, ?, ?, ?, 'running', CURRENT_TIMESTAMP)
  `).run(data.id, data.userId, data.ttpId, data.ttpTitle || null, data.targetsCount);
};

export const getPresenceScanRun = (id: string) => {
  return db.prepare('SELECT * FROM presence_scan_runs WHERE id = ?').get(id) as any;
};

export const getUserPresenceScanRuns = (userId: number) => {
  return db.prepare('SELECT * FROM presence_scan_runs WHERE user_id = ? ORDER BY created_at DESC').all(userId) as any[];
};

export const updatePresenceScanRun = (id: string, updates: Record<string, any>) => {
  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = Object.values(updates);
  return db.prepare(`UPDATE presence_scan_runs SET ${setClauses} WHERE id = ?`).run(...values, id);
};

export const addPresenceScanTarget = (data: {
  runId: string; targetRaw: string; targetUrl: string;
  targetHost?: string; targetPort?: number; targetScheme?: string;
}) => {
  return db.prepare(`
    INSERT INTO presence_scan_targets (run_id, target_raw, target_url, target_host, target_port, target_scheme)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(data.runId, data.targetRaw, data.targetUrl, data.targetHost || null, data.targetPort || null, data.targetScheme || null);
};

export const updatePresenceScanTarget = (id: number, updates: Record<string, any>) => {
  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = Object.values(updates);
  return db.prepare(`UPDATE presence_scan_targets SET ${setClauses} WHERE id = ?`).run(...values, id);
};

export const getPresenceScanTargets = (runId: string, verdict?: string) => {
  if (verdict) {
    return db.prepare('SELECT * FROM presence_scan_targets WHERE run_id = ? AND verdict = ? ORDER BY id ASC').all(runId, verdict) as any[];
  }
  return db.prepare('SELECT * FROM presence_scan_targets WHERE run_id = ? ORDER BY id ASC').all(runId) as any[];
};

export const addPresenceScanLog = (runId: string, message: string) => {
  try {
    db.prepare('INSERT INTO presence_scan_logs (run_id, message) VALUES (?, ?)').run(runId, message);
  } catch (e: any) {
    logger.error(`Failed to save presence scan log: ${e.message}`);
  }
};

export const getPresenceScanLogs = (runId: string): string[] => {
  const rows = db.prepare('SELECT message FROM presence_scan_logs WHERE run_id = ? ORDER BY id ASC').all(runId) as { message: string }[];
  return rows.map(r => r.message);
};

export const deletePresenceScanRun = (id: string, userId: number) => {
  return db.prepare('DELETE FROM presence_scan_runs WHERE id = ? AND user_id = ?').run(id, userId);
};

export const addPresenceScanRunTTP = (runId: string, ttpId: string, ttpTitle?: string) => {
  return db.prepare('INSERT OR IGNORE INTO presence_scan_run_ttps (run_id, ttp_id, ttp_title) VALUES (?, ?, ?)').run(runId, ttpId, ttpTitle || null);
};

export const getPresenceScanRunTTPs = (runId: string): { ttp_id: string; ttp_title: string | null }[] => {
  return db.prepare('SELECT ttp_id, ttp_title FROM presence_scan_run_ttps WHERE run_id = ? ORDER BY id ASC').all(runId) as any[];
};

// ── TTP Test Playbook Cache ──

export const getCachedPlaybook = (ttpId: string): { content: string; model: string; tokens: number; created_at: string } | undefined => {
  return db.prepare('SELECT content, model, tokens, created_at FROM ttp_test_playbooks WHERE ttp_id = ? ORDER BY created_at DESC LIMIT 1').get(ttpId) as any;
};

export const cachePlaybook = (ttpId: string, content: string, model: string, tokens: number) => {
  db.prepare('INSERT INTO ttp_test_playbooks (ttp_id, content, model, tokens) VALUES (?, ?, ?, ?)').run(ttpId, content, model, tokens);
};

// ── PenPard Browser Session Helpers ──

export const createBrowserSession = (data: {
  id: string; userId: number; scanId?: string; findingId?: number;
  targetUrl?: string; proxyHost?: string; proxyPort?: number;
}) => {
  const safeVal = (v: any) => (v === undefined || v === null) ? null : v;
  return db.prepare(`
    INSERT INTO browser_sessions (id, user_id, scan_id, finding_id, target_url, status, lifecycle_state, mode, current_url, proxy_host, proxy_port)
    VALUES (?, ?, ?, ?, ?, 'launching', 'launching', 'human', ?, ?, ?)
  `).run(
    data.id, data.userId, safeVal(data.scanId), safeVal(data.findingId),
    safeVal(data.targetUrl), safeVal(data.targetUrl),
    safeVal(data.proxyHost), safeVal(data.proxyPort)
  );
};

export const getBrowserSession = (id: string) => {
  return db.prepare('SELECT * FROM browser_sessions WHERE id = ?').get(id) as any;
};

export const getUserBrowserSessions = (userId: number) => {
  return db.prepare('SELECT * FROM browser_sessions WHERE user_id = ? ORDER BY launched_at DESC').all(userId) as any[];
};

export const updateBrowserSession = (id: string, updates: Record<string, any>) => {
  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = Object.values(updates);
  return db.prepare(`UPDATE browser_sessions SET ${setClauses} WHERE id = ?`).run(...values, id);
};

export const closeBrowserSession = (
  sessionId: string,
  updates: {
    lifecycle_state?: BrowserLifecycleState;
    lifecycle_detail?: string | null;
    last_error?: string | null;
    current_url?: string | null;
  } = {},
) => {
  return updateBrowserSession(sessionId, {
    status: 'closed',
    lifecycle_state: updates.lifecycle_state || 'closed',
    lifecycle_detail: updates.lifecycle_detail ?? null,
    last_error: updates.last_error ?? null,
    current_url: updates.current_url ?? null,
    closed_at: new Date().toISOString(),
  });
};

export const addBrowserAction = (data: {
  sessionId: string; actionType: string; actionData?: string;
  pageUrl?: string; pageTitle?: string; source?: string;
}) => {
  const safeVal = (v: any) => (v === undefined || v === null) ? null : v;
  try {
    return db.prepare(`
      INSERT INTO browser_actions (session_id, action_type, action_data, page_url, page_title, source)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      data.sessionId, data.actionType, safeVal(data.actionData),
      safeVal(data.pageUrl), safeVal(data.pageTitle), data.source || 'human'
    );
  } catch (e: any) {
    logger.error(`Failed to save browser action: ${e.message}`);
  }
};

export const getBrowserActions = (sessionId: string) => {
  return db.prepare('SELECT * FROM browser_actions WHERE session_id = ? ORDER BY id ASC').all(sessionId) as any[];
};

export const deleteClosedBrowserSessions = (userId: number) => {
  // browser_actions has ON DELETE CASCADE, so deleting sessions auto-deletes their actions
  const result = db.prepare('DELETE FROM browser_sessions WHERE user_id = ? AND status = ?').run(userId, 'closed');
  return result.changes;
};

// ── Schema Validation ──

/** All tables that must exist for the backend to function correctly. */
const REQUIRED_TABLES = [
  'users', 'whitelists', 'llm_config', 'mcp_servers', 'settings',
  'scans', 'vulnerabilities', 'reports', 'report_snapshots', 'report_exports', 'token_usage', 'scan_logs',
  'scan_chat_messages', 'focused_test_objectives', 'scope_envelopes', 'scoped_test_requests', 'scoped_feature_discovery_states', 'focused_test_cases',
  'focused_test_case_executions', 'focused_test_case_execution_trace_entries', 'focused_reasoning_trace_entries', 'focused_test_case_evidence_bundles', 'focused_test_case_verdicts', 'focused_test_case_findings',
  'focused_scan_verdict_summaries', 'focused_test_case_investigation_issues', 'focused_scan_blocker_summaries',
  'focused_scan_historical_compare_states', 'focused_test_case_historical_compares', 'focused_scan_historical_compare_summaries',
  'report_analyses', 'analysis_findings', 'analysis_logs',
  'mindset_ttps', 'mindset_profile', 'ttp_test_playbooks',
  'presence_scan_runs', 'presence_scan_targets', 'presence_scan_logs', 'presence_scan_run_ttps',
  'browser_sessions', 'browser_actions', 'user_integrations', 'integration_auth_sessions',
];

/**
 * Validates that the database schema contains all required tables.
 * Throws an error with a clear message listing missing tables if the schema is incomplete.
 */
export function validateSchema(database?: DatabaseType): void {
  const targetDb = database || db;
  const existing = targetDb
    .prepare("SELECT name FROM sqlite_master WHERE type='table'")
    .all() as { name: string }[];
  const existingNames = new Set(existing.map(r => r.name));
  const missing = REQUIRED_TABLES.filter(t => !existingNames.has(t));

  if (missing.length > 0) {
    throw new Error(
      `DATABASE SCHEMA INCOMPLETE — missing ${missing.length} required table(s): ${missing.join(', ')}. ` +
      `Run the backend normally to auto-create all tables, or delete the DB file and restart. ` +
      `Do NOT use the CLI --recreate_db_danger command with an outdated CLI version.`
    );
  }
}

/**
 * Marks scans stuck in non-terminal states as 'interrupted' after a backend restart.
 * Called once during startup to clean up orphaned scan records.
 */
export function recoverOrphanedScans(): number {
  const nonTerminalStatuses = ['queued', 'initializing', 'planning', 'testing', 'reporting', 'auditing', 'crawling', 'analyzing', 'paused', 'scoped_discovering', 'scoped_executing'];
  const placeholders = nonTerminalStatuses.map(() => '?').join(',');
  const result = db.prepare(`
    UPDATE scans SET status = 'interrupted', error_message = 'Backend restarted while scan was in progress. Scan state was lost.', completed_at = CURRENT_TIMESTAMP
    WHERE status IN (${placeholders})
  `).run(...nonTerminalStatuses);
  return result.changes;
}
