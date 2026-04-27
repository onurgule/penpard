import type {
    FocusedBrowserStep,
    FocusedExecutionAction,
    FocusedTestCase,
    ScopeEnvelope,
    ScopeViolationRecord,
} from './ScopedScanTypes';

export interface FocusedExecutionRequestIntent {
    type: FocusedExecutionAction['type'];
    method?: string;
    url?: string;
    useInitialRequestBaseline?: boolean;
}

export interface FocusedBrowserIntent {
    step: FocusedBrowserStep;
    currentUrl?: string | null;
    browserActionsUsed: number;
    navigationDepth: number;
    verificationRetries: number;
}

export interface FocusedScopeGuardDecision {
    allowed: boolean;
    normalizedHost?: string;
    normalizedPath?: string;
    violation?: ScopeViolationRecord;
}

export class FocusedScopeGuard {
    public evaluate(input: {
        action: FocusedExecutionRequestIntent;
        testCase: FocusedTestCase;
        envelope: ScopeEnvelope;
    }): FocusedScopeGuardDecision {
        const normalizedPath = this.normalizeRoutePath(input.action.url);
        const normalizedHost = this.normalizeHost(input.action.url);
        const attemptedMethod = typeof input.action.method === 'string' ? input.action.method.toUpperCase() : undefined;
        const now = new Date().toISOString();

        const scopeDecision = this.evaluateScope({
            attemptedAction: input.action.type,
            attemptedMethod,
            normalizedHost,
            normalizedPath,
            testCase: input.testCase,
            envelope: input.envelope,
            now,
            useInitialRequestBaseline: input.action.useInitialRequestBaseline,
        });
        if (!scopeDecision.allowed) {
            return scopeDecision;
        }

        return {
            allowed: true,
            normalizedHost,
            normalizedPath,
        };
    }

    public evaluateBrowserStep(input: {
        browser: FocusedBrowserIntent;
        testCase: FocusedTestCase;
        envelope: ScopeEnvelope;
    }): FocusedScopeGuardDecision {
        const budgetDecision = this.evaluateBrowserBudget(input.browser, input.envelope);
        if (!budgetDecision.allowed) {
            return budgetDecision;
        }

        const targetUrl = input.browser.step.url || input.browser.currentUrl || undefined;
        const normalizedPath = this.normalizeRoutePath(targetUrl);
        const normalizedHost = this.normalizeHost(targetUrl);
        const now = new Date().toISOString();

        if (input.browser.step.action === 'goto' || input.browser.step.action === 'reload') {
            return this.evaluateScope({
                attemptedAction: input.browser.step.action,
                normalizedHost,
                normalizedPath,
                testCase: input.testCase,
                envelope: input.envelope,
                now,
            });
        }

        return {
            allowed: true,
            normalizedHost,
            normalizedPath,
        };
    }

    public evaluateBrowserLocation(input: {
        action: FocusedBrowserStep['action'];
        url?: string | null;
        testCase: FocusedTestCase;
        envelope: ScopeEnvelope;
        navigationDepth: number;
        verificationRetries: number;
        browserActionsUsed: number;
    }): FocusedScopeGuardDecision {
        const budgetDecision = this.evaluateBrowserBudget({
            step: { action: input.action, summary: input.action },
            currentUrl: input.url,
            browserActionsUsed: input.browserActionsUsed,
            navigationDepth: input.navigationDepth,
            verificationRetries: input.verificationRetries,
        }, input.envelope);
        if (!budgetDecision.allowed) {
            return budgetDecision;
        }

        const normalizedPath = this.normalizeRoutePath(input.url || undefined);
        const normalizedHost = this.normalizeHost(input.url || undefined);
        const now = new Date().toISOString();

        return this.evaluateScope({
            attemptedAction: input.action,
            normalizedHost,
            normalizedPath,
            testCase: input.testCase,
            envelope: input.envelope,
            now,
        });
    }

    private evaluateBrowserBudget(browser: FocusedBrowserIntent, envelope: ScopeEnvelope): FocusedScopeGuardDecision {
        const now = new Date().toISOString();
        const maxBrowserActions = envelope.explorationBudget?.maxBrowserActions ?? null;
        const maxNavigationDepth = envelope.explorationBudget?.maxNavigationDepth ?? null;
        const maxVerificationRetries = envelope.explorationBudget?.maxVerificationRetries ?? null;

        if (maxBrowserActions !== null && browser.browserActionsUsed >= maxBrowserActions) {
            return {
                allowed: false,
                violation: {
                    reason: `Browser action budget of ${maxBrowserActions} was exhausted for this focused case.`,
                    attemptedAction: browser.step.action,
                    violationKind: 'budget',
                    blockedAt: now,
                },
            };
        }

        if (maxNavigationDepth !== null && browser.navigationDepth > maxNavigationDepth) {
            return {
                allowed: false,
                violation: {
                    reason: `Browser navigation depth exceeded the scoped limit of ${maxNavigationDepth}.`,
                    attemptedAction: browser.step.action,
                    violationKind: 'budget',
                    blockedAt: now,
                },
            };
        }

        if (maxVerificationRetries !== null && browser.verificationRetries > maxVerificationRetries) {
            return {
                allowed: false,
                violation: {
                    reason: `Browser verification retries exceeded the scoped limit of ${maxVerificationRetries}.`,
                    attemptedAction: browser.step.action,
                    violationKind: 'budget',
                    blockedAt: now,
                },
            };
        }

        return { allowed: true };
    }

    private evaluateScope(input: {
        attemptedAction: FocusedExecutionAction['type'] | FocusedBrowserStep['action'];
        attemptedMethod?: string;
        normalizedHost?: string;
        normalizedPath?: string;
        testCase: FocusedTestCase;
        envelope: ScopeEnvelope;
        now: string;
        useInitialRequestBaseline?: boolean;
    }): FocusedScopeGuardDecision {
        if (input.normalizedHost && input.envelope.allowedHosts.length > 0 && !input.envelope.allowedHosts.includes(input.normalizedHost)) {
            return {
                allowed: false,
                normalizedHost: input.normalizedHost,
                normalizedPath: input.normalizedPath,
                violation: {
                    reason: `Attempted host ${input.normalizedHost} is outside the persisted scope envelope.`,
                    attemptedAction: input.attemptedAction,
                    attemptedHost: input.normalizedHost,
                    attemptedPath: input.normalizedPath,
                    attemptedMethod: input.attemptedMethod,
                    violationKind: 'host',
                    blockedAt: input.now,
                },
            };
        }

        if (input.normalizedPath && input.envelope.allowedRoutes.length > 0) {
            const allowedRoute = input.envelope.allowedRoutes.find((route) => this.routeMatches(route, input.normalizedPath!));
            if (!allowedRoute) {
                return {
                    allowed: false,
                    normalizedHost: input.normalizedHost,
                    normalizedPath: input.normalizedPath,
                    violation: {
                        reason: `Attempted path ${input.normalizedPath} is outside the persisted allowed routes.`,
                        attemptedAction: input.attemptedAction,
                        attemptedHost: input.normalizedHost,
                        attemptedPath: input.normalizedPath,
                        attemptedMethod: input.attemptedMethod,
                        violationKind: 'route',
                        blockedAt: input.now,
                    },
                };
            }
        }

        const targetPath = this.normalizeRoutePath(input.testCase.targetArtifact.path || input.testCase.targetArtifact.url);
        const targetMethod = input.testCase.targetArtifact.method?.toUpperCase();
        if (input.testCase.targetArtifact.kind === 'endpoint') {
            const endpointMatch = input.envelope.selectedEndpoints.some((endpoint) => {
                const endpointMethod = endpoint.method?.toUpperCase();
                const endpointPath = this.normalizeRoutePath(endpoint.path || endpoint.url);
                return (!targetMethod || endpointMethod === targetMethod)
                    && !!endpointPath
                    && !!targetPath
                    && this.routeMatches(endpointPath, targetPath);
            });

            if (targetPath && input.normalizedPath) {
                const methodMatchesTarget = !targetMethod || !input.attemptedMethod || targetMethod === input.attemptedMethod;
                const pathMatchesTarget = this.routeMatches(targetPath, input.normalizedPath);
                if (!methodMatchesTarget || !pathMatchesTarget || (!endpointMatch && input.envelope.selectedEndpoints.length > 0)) {
                    return {
                        allowed: false,
                        normalizedHost: input.normalizedHost,
                        normalizedPath: input.normalizedPath,
                        violation: {
                            reason: 'Endpoint-scoped execution attempted a method/path that does not match the approved selected endpoint.',
                            attemptedAction: input.attemptedAction,
                            attemptedHost: input.normalizedHost,
                            attemptedPath: input.normalizedPath,
                            attemptedMethod: input.attemptedMethod,
                            violationKind: 'endpoint_target',
                            blockedAt: input.now,
                        },
                    };
                }
            }
        }

        if (input.testCase.targetArtifact.kind === 'baseline_request' && input.useInitialRequestBaseline === false) {
            return {
                allowed: false,
                normalizedHost: input.normalizedHost,
                normalizedPath: input.normalizedPath,
                violation: {
                    reason: 'Baseline-request scoped execution must remain anchored to the persisted Burp baseline request.',
                    attemptedAction: input.attemptedAction,
                    attemptedHost: input.normalizedHost,
                    attemptedPath: input.normalizedPath,
                    attemptedMethod: input.attemptedMethod,
                    violationKind: 'baseline_anchor',
                    blockedAt: input.now,
                },
            };
        }

        if (input.testCase.targetArtifact.kind === 'baseline_request' && targetPath && input.normalizedPath && !this.routeMatches(targetPath, input.normalizedPath)) {
            return {
                allowed: false,
                normalizedHost: input.normalizedHost,
                normalizedPath: input.normalizedPath,
                violation: {
                    reason: 'Baseline-request scoped browser execution attempted a location outside the persisted request anchor.',
                    attemptedAction: input.attemptedAction,
                    attemptedHost: input.normalizedHost,
                    attemptedPath: input.normalizedPath,
                    attemptedMethod: input.attemptedMethod,
                    violationKind: 'baseline_anchor',
                    blockedAt: input.now,
                },
            };
        }

        return {
            allowed: true,
            normalizedHost: input.normalizedHost,
            normalizedPath: input.normalizedPath,
        };
    }

    private normalizeHost(value?: string): string | undefined {
        if (!value) {
            return undefined;
        }

        try {
            return new URL(value).host.toLowerCase();
        } catch {
            return value
                .trim()
                .toLowerCase()
                .replace(/^https?:\/\//i, '')
                .replace(/\/.*$/, '');
        }
    }

    private normalizeRoutePath(value?: string): string | undefined {
        if (!value) {
            return undefined;
        }

        try {
            const parsed = new URL(value);
            return parsed.pathname || '/';
        } catch {
            const withoutQuery = value.split('?')[0]?.split('#')[0]?.trim();
            if (!withoutQuery) {
                return undefined;
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
}

export const focusedScopeGuard = new FocusedScopeGuard();
