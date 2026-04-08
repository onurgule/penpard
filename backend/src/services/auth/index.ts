/**
 * PenPard Auth State Management — Barrel Export
 * 
 * Import everything from: import { AuthStateManager, AuthInjector, ... } from '../services/auth';
 */

export { AuthStateManager } from './AuthStateManager';
export { AuthInjector } from './AuthInjector';
export { AuthCapture } from './AuthCapture';
export { CookieJar } from './CookieJar';
export { TokenStore } from './TokenStore';
export { CSRFManager } from './CSRFManager';
export { IdentityRegistry } from './IdentityRegistry';
export { SessionHealthMonitor } from './SessionHealthMonitor';

// Re-export all types
export type {
    AuthCaptureSource,
    CredentialSource,
    IdentityRole,
    SessionStatus,
    SessionProbeResult,
    TokenType,
    CSRFDeliveryMechanism,
    RefreshStrategy,
    LoginMethod,
    AuthStartupMode,
    CredentialPrivilege,
    AuthSurfaceType,
    IdentityProfile,
    CredentialSet,
    AuthStartupCredential,
    AuthStartupConfig,
    AuthInventoryField,
    AuthInventoryElement,
    AuthInventoryForm,
    AuthTrafficObservation,
    AuthStartupActionRecord,
    AuthTransportSummary,
    AuthStartupInventory,
    SessionState,
    TokenState,
    CookieEntry,
    CSRFState,
    RefreshPlan,
    SessionHealth,
    AuthContext,
    AuthContextHeaders,
    RequestAuthDiagnostics,
    RequestAuthIntent,
    AuthEvidence,
    RequestAuthBindingRules,
    AuthExport,
    AuthExportIdentity,
    AuthEventType,
    AuthEvent,
} from './types';

export {
    SESSION_COOKIE_PATTERNS,
    CSRF_COOKIE_PATTERNS,
    CSRF_PARAM_NAMES,
    CSRF_HEADER_NAMES,
    LOGIN_PATH_PATTERNS,
    DEFAULT_NO_AUTH_PATHS,
    AUTH_BOOTSTRAP_PATH_PATTERNS,
    redactSecret,
} from './types';
