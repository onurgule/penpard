import { v4 as uuidv4 } from 'uuid';
import { browserService } from '../BrowserService';
import { createEvidenceBundle } from '../../db/init';
import { logger } from '../../utils/logger';
import type { AuthStateManager } from '../auth/AuthStateManager';
import type {
    EvidenceBundle,
    FocusedBrowserActionRecord,
    FocusedBrowserEvidence,
    FocusedBrowserExpectation,
    FocusedBrowserExpectationResult,
    FocusedBrowserPlan,
    FocusedBrowserStep,
    FocusedEvidenceScreenshotRef,
    FocusedTestCase,
    ScopeEnvelope,
} from './ScopedScanTypes';
import { focusedScopeGuard, type FocusedScopeGuard } from './FocusedScopeGuard';
import type { FocusedInvestigationObservation } from './FocusedInvestigationService';

interface BrowserServiceLike {
    launchSession(userId: number, options?: { targetUrl?: string; scanId?: string; label?: string; headless?: boolean }): Promise<string>;
    syncCookiesToSession(sessionId: string, cookies: Array<{
        name: string;
        value: string;
        domain: string;
        path: string;
        expires: number;
        httpOnly: boolean;
        secure: boolean;
        sameSite: 'Strict' | 'Lax' | 'None';
    }>): Promise<number>;
    executeAction(sessionId: string, action: {
        type: string;
        url?: string;
        selector?: string;
        value?: string;
        timeout?: number;
    }): Promise<any>;
    getPageState(sessionId: string): Promise<{ url: string; title: string; textSummary?: string }>;
    getFullPageState(sessionId: string): Promise<any>;
    captureScreenshot(sessionId: string): Promise<{ base64: string; mimeType: string }>;
    closeSession(sessionId: string): Promise<void>;
}

export interface FocusedBrowserAnchor {
    startUrl: string;
    source: 'target_artifact' | 'selected_endpoint' | 'baseline_request' | 'allowed_route' | 'request_url' | 'discovered_request' | 'discovered_browser';
}

export interface FocusedBrowserFlowInput {
    scanId: string;
    userId: number;
    executionId: string;
    testCase: FocusedTestCase;
    envelope: ScopeEnvelope;
    authManager: AuthStateManager;
    anchor: FocusedBrowserAnchor;
    plan: FocusedBrowserPlan;
    profileKey: string;
    profileProvider?: string | null;
    profileModel?: string | null;
    relatedEvidenceBundles?: EvidenceBundle[];
}

export interface FocusedBrowserFlowResult {
    executionState: 'completed' | 'blocked' | 'failed_to_execute';
    notesSummary: string;
    errorMessage?: string | null;
    browserActionsUsed: number;
    browserSessionId: string | null;
    evidenceBundle: EvidenceBundle | null;
    evidenceIds: string[];
    scopeViolationReason?: string | null;
    investigationObservations: FocusedInvestigationObservation[];
}

interface BrowserRunnerDependencies {
    browser: BrowserServiceLike;
    scopeGuard: FocusedScopeGuard;
    now: () => string;
    createId: () => string;
}

const WAIT_ACTIONS = new Set(['waitForNavigation', 'waitForSelector']);
const NAVIGATION_ACTIONS = new Set(['goto', 'submit', 'waitForNavigation', 'reload']);

export class FocusedBrowserFlowRunner {
    constructor(
        private readonly deps: BrowserRunnerDependencies = {
            browser: browserService,
            scopeGuard: focusedScopeGuard,
            now: () => new Date().toISOString(),
            createId: () => uuidv4(),
        },
    ) {}

    public async execute(input: FocusedBrowserFlowInput): Promise<FocusedBrowserFlowResult> {
        let sessionId: string | null = null;
        let browserActionsUsed = 0;
        let navigationDepth = 0;
        let verificationRetries = 0;
        const actionRecords: FocusedBrowserActionRecord[] = [];

        const relatedEvidenceIds = (input.relatedEvidenceBundles || []).map((bundle) => bundle.id);
        const plannedSteps = this.ensureStartNavigation(input.anchor.startUrl, input.plan.steps || []);

        try {
            sessionId = await this.deps.browser.launchSession(input.userId, {
                scanId: input.scanId,
                targetUrl: 'about:blank',
                label: `focused:${input.testCase.id}`,
                headless: true,
            });

            const targetHost = this.safeHostname(input.anchor.startUrl);
            const seededCookies = input.authManager.exportForBrowser('primary-user', targetHost || undefined);
            if (seededCookies.length > 0) {
                await this.deps.browser.syncCookiesToSession(sessionId, seededCookies);
            }

            for (const step of plannedSteps) {
                const precheck = this.deps.scopeGuard.evaluateBrowserStep({
                    browser: {
                        step,
                        browserActionsUsed,
                        navigationDepth,
                        verificationRetries,
                    },
                    testCase: input.testCase,
                    envelope: input.envelope,
                });
                if (!precheck.allowed && precheck.violation) {
                    const evidence = this.persistScopeViolation(input, precheck.violation, sessionId, relatedEvidenceIds);
                    return {
                        executionState: 'blocked',
                        notesSummary: precheck.violation.reason,
                        browserActionsUsed,
                        browserSessionId: sessionId,
                        evidenceBundle: evidence,
                        evidenceIds: [evidence.id],
                        scopeViolationReason: precheck.violation.reason,
                        investigationObservations: this.buildScopeViolationObservations(input, precheck.violation, [evidence.id]),
                    };
                }

                const result = await this.deps.browser.executeAction(sessionId, this.toBrowserAction(step));
                browserActionsUsed += 1;
                if (WAIT_ACTIONS.has(step.action)) {
                    verificationRetries += 1;
                }
                if (NAVIGATION_ACTIONS.has(step.action)) {
                    navigationDepth += 1;
                }

                const pageState = await this.deps.browser.getPageState(sessionId);
                const postcheck = this.deps.scopeGuard.evaluateBrowserLocation({
                    action: step.action,
                    url: pageState.url,
                    testCase: input.testCase,
                    envelope: input.envelope,
                    browserActionsUsed,
                    navigationDepth,
                    verificationRetries,
                });
                if (!postcheck.allowed && postcheck.violation) {
                    const evidence = this.persistScopeViolation(input, postcheck.violation, sessionId, relatedEvidenceIds);
                    return {
                        executionState: 'blocked',
                        notesSummary: postcheck.violation.reason,
                        browserActionsUsed,
                        browserSessionId: sessionId,
                        evidenceBundle: evidence,
                        evidenceIds: [evidence.id],
                        scopeViolationReason: postcheck.violation.reason,
                        investigationObservations: this.buildScopeViolationObservations(input, postcheck.violation, [evidence.id], pageState.url || null),
                    };
                }

                actionRecords.push({
                    action: step.action,
                    summary: step.summary,
                    targetUrl: step.url ?? null,
                    selector: step.selector ?? null,
                    valuePreview: step.value ? this.truncate(step.value, 80) : null,
                    resultingUrl: pageState.url || result?.url || null,
                    resultingPath: this.normalizeRoutePath(pageState.url || result?.url || null),
                    resultingTitle: pageState.title || result?.title || null,
                    capturedAt: this.deps.now(),
                });
            }

            const finalPageState = await this.deps.browser.getFullPageState(sessionId);
            const screenshot = await this.captureScreenshotRef(sessionId, 'Final focused browser proof');
            const screenshots = screenshot ? [screenshot] : [];
            input.authManager.syncFromBrowser(Array.isArray(finalPageState?.contextCookies) ? finalPageState.contextCookies : []);
            input.authManager.syncFromBrowserStorage({
                localStorageData: finalPageState?.localStorageData || undefined,
                sessionStorageData: finalPageState?.sessionStorageData || undefined,
            });
            input.authManager.detectCSRFFromPage(finalPageState);

            const expectationResults = this.evaluateExpectations(input.plan.expectations || [], finalPageState, input.relatedEvidenceBundles || []);
            const browserEvidence = this.buildBrowserEvidence({
                input,
                sessionId,
                actionRecords,
                screenshots,
                finalPageState,
                expectationResults,
                browserActionsUsed,
                navigationDepth,
                verificationRetries,
            });
            const summary = browserEvidence.actionSummary;
            const actionType = expectationResults.length > 0 ? 'browser_state_check' : 'browser_sequence';
            const bundle: EvidenceBundle = {
                id: this.deps.createId(),
                scanId: input.scanId,
                caseId: input.testCase.id,
                executionId: input.executionId,
                summary,
                source: relatedEvidenceIds.length > 0 ? 'browser_verification' : 'browser_flow',
                capturedAt: this.deps.now(),
                screenshotRef: screenshots[0] || null,
                browserState: browserEvidence,
                relatedEvidenceIds,
                executionNotes: this.buildExecutionNote(browserEvidence, expectationResults),
                provenance: {
                    profileKey: input.profileKey,
                    actionType,
                    provider: input.profileProvider || undefined,
                    model: input.profileModel || undefined,
                    source: input.profileProvider || input.profileModel ? 'model' : 'system',
                },
            };
            createEvidenceBundle(bundle);

            const investigationObservations = [
                ...this.buildExpectationMismatchObservations(bundle),
                ...this.buildAuthSessionDriftObservations(input, bundle),
            ];

            return {
                executionState: 'completed',
                notesSummary: bundle.executionNotes || summary,
                browserActionsUsed,
                browserSessionId: sessionId,
                evidenceBundle: bundle,
                evidenceIds: [bundle.id],
                investigationObservations,
            };
        } catch (error: any) {
            logger.warn('Focused browser flow execution failed', {
                scanId: input.scanId,
                caseId: input.testCase.id,
                error: error.message,
            });
            return {
                executionState: 'failed_to_execute',
                notesSummary: 'Focused browser/stateful verification failed before proof could be completed.',
                errorMessage: error.message,
                browserActionsUsed,
                browserSessionId: sessionId,
                evidenceBundle: null,
                evidenceIds: [],
                investigationObservations: [{
                    issueType: 'environment_instability',
                    issueTitle: 'Focused browser verification failed before proof could be captured.',
                    issueDetails: error.message,
                    issueStatus: 'open',
                    impact: 'degrading',
                    source: 'system',
                    correlation: {
                        executionState: 'failed_to_execute',
                        browserActionType: 'goto',
                    },
                }],
            };
        } finally {
            if (sessionId) {
                try {
                    await this.deps.browser.closeSession(sessionId);
                } catch {
                    /* ignore cleanup failure */
                }
            }
        }
    }

    private ensureStartNavigation(startUrl: string, steps: FocusedBrowserStep[]): FocusedBrowserStep[] {
        if (steps[0]?.action === 'goto') {
            return steps;
        }
        return [{
            action: 'goto',
            summary: `Open the approved in-scope start route ${this.normalizeRoutePath(startUrl) || startUrl}.`,
            url: startUrl,
        }, ...steps];
    }

    private toBrowserAction(step: FocusedBrowserStep): { type: string; url?: string; selector?: string; value?: string; timeout?: number } {
        return {
            type: step.action,
            url: step.url,
            selector: step.selector,
            value: step.value,
            timeout: step.timeoutMs,
        };
    }

    private evaluateExpectations(
        expectations: FocusedBrowserExpectation[],
        finalPageState: any,
        relatedEvidenceBundles: EvidenceBundle[],
    ): FocusedBrowserExpectationResult[] {
        const pageUrl = String(finalPageState?.url || '');
        const pageTitle = String(finalPageState?.title || '');
        const pageText = String(finalPageState?.textSummary || '').toLowerCase();
        const relatedChanges = relatedEvidenceBundles
            .map((bundle) => bundle.responseDiffSummary?.summary)
            .filter((entry): entry is string => !!entry);

        return expectations.map((expectation) => {
            const expectedValue = expectation.value || null;
            const loweredExpected = String(expectedValue || '').toLowerCase();
            let matched = false;
            let observedSummary = '';

            switch (expectation.matcher) {
                case 'page_loaded':
                    matched = !!pageUrl && pageUrl !== 'about:blank';
                    observedSummary = pageUrl || 'No page URL was available after the browser steps.';
                    break;
                case 'path_matches': {
                    const path = this.normalizeRoutePath(pageUrl) || '';
                    matched = !!expectedValue && this.routeMatches(String(expectedValue), path);
                    observedSummary = path || 'No final path was available.';
                    break;
                }
                case 'text_contains':
                    matched = !!loweredExpected && pageText.includes(loweredExpected);
                    observedSummary = matched
                        ? `Page text contains "${expectedValue}".`
                        : `Page text did not contain "${expectedValue}".`;
                    break;
                case 'text_absent':
                    matched = !!loweredExpected && !pageText.includes(loweredExpected);
                    observedSummary = matched
                        ? `Page text does not include "${expectedValue}".`
                        : `Page text still includes "${expectedValue}".`;
                    break;
                case 'title_contains':
                    matched = !!loweredExpected && pageTitle.toLowerCase().includes(loweredExpected);
                    observedSummary = pageTitle || 'No page title was available.';
                    break;
                case 'state_changed':
                    matched = relatedChanges.length > 0 || (!!loweredExpected && pageText.includes(loweredExpected));
                    observedSummary = relatedChanges[0]
                        || (expectedValue ? `Observed page contains the expected changed state marker "${expectedValue}".` : 'Observed a state-change marker in the combined request/browser evidence.');
                    break;
                case 'state_unchanged':
                    matched = relatedChanges.length === 0 && (!loweredExpected || !pageText.includes(loweredExpected));
                    observedSummary = relatedChanges[0]
                        ? `Related request evidence already signaled change: ${relatedChanges[0]}`
                        : 'No persisted change markers were found in the combined request/browser evidence.';
                    break;
                default:
                    observedSummary = 'Expectation matcher is not recognized.';
                    matched = false;
                    break;
            }

            return {
                kind: expectation.kind,
                description: expectation.description,
                matcher: expectation.matcher,
                matched,
                expected: expectedValue,
                observedSummary,
            };
        });
    }

    private buildBrowserEvidence(input: {
        input: FocusedBrowserFlowInput;
        sessionId: string;
        actionRecords: FocusedBrowserActionRecord[];
        screenshots: FocusedEvidenceScreenshotRef[];
        finalPageState: any;
        expectationResults: FocusedBrowserExpectationResult[];
        browserActionsUsed: number;
        navigationDepth: number;
        verificationRetries: number;
    }): FocusedBrowserEvidence {
        const finalUrl = String(input.finalPageState?.url || input.actionRecords[input.actionRecords.length - 1]?.resultingUrl || input.input.anchor.startUrl);
        const finalPath = this.normalizeRoutePath(finalUrl);
        const relatedRequestEvidenceIds = (input.input.relatedEvidenceBundles || []).map((bundle) => bundle.id);
        const relatedChanges = (input.input.relatedEvidenceBundles || [])
            .map((bundle) => bundle.responseDiffSummary?.summary)
            .filter((entry): entry is string => !!entry);

        return {
            sessionId: input.sessionId,
            startUrl: input.input.anchor.startUrl,
            finalUrl,
            finalPath,
            pageTitle: input.finalPageState?.title || null,
            actionCount: input.browserActionsUsed,
            navigationDepth: input.navigationDepth,
            verificationRetries: input.verificationRetries,
            actionSummary: this.buildBrowserSummary(input.input.plan.summary, input.actionRecords, input.expectationResults),
            domSummary: this.truncate(String(input.finalPageState?.textSummary || ''), 600) || null,
            stateNotes: [
                input.finalPageState?.title ? `Final page title: ${input.finalPageState.title}` : null,
                finalPath ? `Final path: ${finalPath}` : null,
                input.expectationResults.length > 0 ? `${input.expectationResults.filter((entry) => entry.matched).length}/${input.expectationResults.length} browser expectations matched.` : null,
            ].filter((entry): entry is string => !!entry),
            detectedChanges: relatedChanges,
            actions: input.actionRecords,
            expectations: input.expectationResults,
            screenshots: input.screenshots,
            relatedRequestEvidenceIds,
        };
    }

    private buildBrowserSummary(planSummary: string, actionRecords: FocusedBrowserActionRecord[], expectationResults: FocusedBrowserExpectationResult[]): string {
        const summaryParts = [
            planSummary?.trim(),
            actionRecords.length > 0 ? `${actionRecords.length} bounded browser step(s) executed.` : null,
            expectationResults.length > 0
                ? `${expectationResults.filter((entry) => entry.matched).length}/${expectationResults.length} browser checks matched.`
                : null,
        ].filter((entry): entry is string => !!entry);
        return summaryParts.join(' ').slice(0, 280) || 'Captured bounded browser/stateful evidence.';
    }

    private buildExecutionNote(browserEvidence: FocusedBrowserEvidence, expectationResults: FocusedBrowserExpectationResult[]): string {
        const failedExpectation = expectationResults.find((entry) => !entry.matched);
        if (failedExpectation) {
            return `${browserEvidence.actionSummary} Check failed: ${failedExpectation.observedSummary}`.slice(0, 500);
        }
        return browserEvidence.actionSummary.slice(0, 500);
    }

    private async captureScreenshotRef(sessionId: string, label: string): Promise<FocusedEvidenceScreenshotRef | null> {
        try {
            const screenshot = await this.deps.browser.captureScreenshot(sessionId);
            if (!screenshot?.base64) {
                return null;
            }
            return {
                kind: 'browser_session_base64',
                value: screenshot.base64,
                mimeType: screenshot.mimeType,
                label,
                capturedAt: this.deps.now(),
            };
        } catch {
            return null;
        }
    }

    private persistScopeViolation(
        input: FocusedBrowserFlowInput,
        violation: NonNullable<ReturnType<FocusedScopeGuard['evaluateBrowserLocation']>['violation']>,
        sessionId: string | null,
        relatedEvidenceIds: string[],
    ): EvidenceBundle {
        const bundle: EvidenceBundle = {
            id: this.deps.createId(),
            scanId: input.scanId,
            caseId: input.testCase.id,
            executionId: input.executionId,
            summary: violation.reason,
            source: 'scope_guard',
            capturedAt: this.deps.now(),
            relatedEvidenceIds,
            executionNotes: violation.reason,
            provenance: {
                profileKey: input.profileKey,
                actionType: 'browser_sequence',
                provider: input.profileProvider || undefined,
                model: input.profileModel || undefined,
                source: input.profileProvider || input.profileModel ? 'model' : 'system',
            },
            scopeViolation: violation,
            browserState: sessionId ? {
                sessionId,
                startUrl: input.anchor.startUrl,
                finalUrl: null,
                finalPath: null,
                pageTitle: null,
                actionCount: 0,
                navigationDepth: 0,
                verificationRetries: 0,
                actionSummary: violation.reason,
                stateNotes: [],
                detectedChanges: [],
                actions: [],
                expectations: [],
                screenshots: [],
                relatedRequestEvidenceIds: relatedEvidenceIds,
            } : null,
        };
        createEvidenceBundle(bundle);
        return bundle;
    }

    private buildScopeViolationObservations(
        input: FocusedBrowserFlowInput,
        violation: NonNullable<ReturnType<FocusedScopeGuard['evaluateBrowserLocation']>['violation']>,
        linkedEvidenceIds: string[],
        observedUrl?: string | null,
    ): FocusedInvestigationObservation[] {
        const observations: FocusedInvestigationObservation[] = [{
            issueType: violation.violationKind === 'budget' ? 'execution_budget_exhausted' : 'scope_violation',
            issueTitle: violation.violationKind === 'budget'
                ? 'Focused browser execution exhausted a scoped browser budget.'
                : 'Focused browser execution left the approved scoped boundary.',
            issueDetails: violation.reason,
            issueStatus: 'open',
            impact: violation.violationKind === 'budget' ? 'degrading' : 'blocking',
            source: 'system',
            linkedEvidenceIds,
            correlation: {
                executionState: 'blocked',
                browserActionType: violation.attemptedAction as any,
                scopeViolationKinds: [violation.violationKind],
                observedPath: this.normalizeRoutePath(observedUrl || violation.attemptedPath || null) || undefined,
            },
        }];

        if (violation.violationKind !== 'budget') {
            observations.push({
                issueType: 'unexpected_navigation',
                issueTitle: 'Focused browser flow navigated outside the expected in-scope route.',
                issueDetails: violation.reason,
                issueStatus: 'open',
                impact: 'degrading',
                source: 'system',
                linkedEvidenceIds,
                correlation: {
                    executionState: 'blocked',
                    browserActionType: violation.attemptedAction as any,
                    observedPath: this.normalizeRoutePath(observedUrl || violation.attemptedPath || null) || undefined,
                    anchorPath: this.normalizeRoutePath(input.anchor.startUrl) || undefined,
                },
            });
        }

        return observations;
    }

    private buildExpectationMismatchObservations(bundle: EvidenceBundle): FocusedInvestigationObservation[] {
        const failedExpectations = bundle.browserState?.expectations?.filter((entry) => !entry.matched) || [];
        if (failedExpectations.length === 0) {
            return [];
        }

        return [{
            issueType: 'browser_state_mismatch',
            issueTitle: 'Focused browser verification did not match the expected rendered state.',
            issueDetails: failedExpectations.map((entry) => `${entry.description}: ${entry.observedSummary}`).join(' ').slice(0, 500),
            issueStatus: 'open',
            impact: 'degrading',
            source: 'system',
            linkedEvidenceIds: [bundle.id],
            workaroundAttempts: bundle.relatedEvidenceIds?.length
                ? [{
                    attemptedAt: bundle.capturedAt,
                    summary: 'Attempted bounded browser verification after collecting request evidence.',
                    outcome: 'no_change',
                    linkedEvidenceIds: [bundle.id, ...bundle.relatedEvidenceIds],
                  }]
                : [],
            correlation: {
                executionState: 'completed',
                evidenceSources: [bundle.source],
                observedPath: bundle.browserState?.finalPath || undefined,
            },
        }];
    }

    private buildAuthSessionDriftObservations(
        input: FocusedBrowserFlowInput,
        bundle: EvidenceBundle,
    ): FocusedInvestigationObservation[] {
        const finalPath = this.normalizeRoutePath(bundle.browserState?.finalPath || bundle.browserState?.finalUrl || null);
        const title = String(bundle.browserState?.pageTitle || '').toLowerCase();
        const looksLoggedOut = finalPath === '/login'
            || finalPath === '/signin'
            || finalPath === '/sign-in'
            || title.includes('sign in')
            || title.includes('login');
        const authContext = input.envelope.authContext;

        if (!looksLoggedOut || (!authContext?.hasSessionCookies && !authContext?.providedCredentialCount)) {
            return [];
        }

        return [{
            issueType: 'auth_session_drift',
            issueTitle: 'Focused browser flow appears to have lost the expected authenticated session.',
            issueDetails: `Browser flow ended on ${finalPath || 'an unauthenticated route'} despite persisted scoped auth context.`,
            issueStatus: 'open',
            impact: 'degrading',
            source: 'system',
            linkedEvidenceIds: [bundle.id],
            correlation: {
                executionState: 'completed',
                evidenceSources: [bundle.source],
                observedPath: finalPath || undefined,
            },
        }];
    }

    private normalizeRoutePath(value?: string | null): string | null {
        if (!value) {
            return null;
        }

        try {
            return new URL(value).pathname || '/';
        } catch {
            const withoutQuery = value.split('?')[0]?.split('#')[0]?.trim();
            if (!withoutQuery) {
                return null;
            }
            return withoutQuery.startsWith('/') ? withoutQuery : `/${withoutQuery}`;
        }
    }

    private routeMatches(pattern: string, candidate: string): boolean {
        const normalizedPattern = this.normalizeRoutePath(pattern);
        const normalizedCandidate = this.normalizeRoutePath(candidate);
        if (!normalizedPattern || !normalizedCandidate) {
            return false;
        }
        if (normalizedPattern === normalizedCandidate) {
            return true;
        }

        const escaped = normalizedPattern
            .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*')
            .replace(/\/:([A-Za-z0-9_]+)/g, '/[^/]+');
        return new RegExp(`^${escaped}$`).test(normalizedCandidate);
    }

    private safeHostname(url: string): string | null {
        try {
            return new URL(url).hostname;
        } catch {
            return null;
        }
    }

    private truncate(value: string, limit: number): string {
        const trimmed = value.trim();
        return trimmed.length > limit ? `${trimmed.slice(0, limit)}...` : trimmed;
    }
}

export const focusedBrowserFlowRunner = new FocusedBrowserFlowRunner();
