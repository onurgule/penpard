export const BROWSER_LIFECYCLE_STATES = [
  'never_started',
  'launching',
  'headless_active',
  'visible_active',
  'hidden',
  'manually_closed',
  'crashed_or_disconnected',
  'stale_reference',
  'closing',
  'closed',
] as const;

export type BrowserLifecycleState = typeof BROWSER_LIFECYCLE_STATES[number];

export const LIVE_BROWSER_LIFECYCLE_STATES = new Set<BrowserLifecycleState>([
  'headless_active',
  'visible_active',
  'hidden',
]);

export function isLiveBrowserLifecycleState(state: BrowserLifecycleState): boolean {
  return LIVE_BROWSER_LIFECYCLE_STATES.has(state);
}

export function deriveActiveBrowserLifecycleState(isHeadless: boolean, hasBeenVisible: boolean): BrowserLifecycleState {
  if (!isHeadless) {
    return 'visible_active';
  }
  return hasBeenVisible ? 'hidden' : 'headless_active';
}
