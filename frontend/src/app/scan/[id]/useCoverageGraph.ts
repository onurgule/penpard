'use client';

/**
 * useCoverageGraph.ts
 *
 * Custom hook that owns all coverage-graph-related state,
 * extracted from MissionControlClient to reduce its complexity.
 *
 * This hook does NOT own fetch logic — it exposes update callbacks
 * that MissionControlClient calls from its existing fetch functions,
 * preserving the exact same polling timing and data flow.
 */

import { useState, useCallback } from 'react';
import type { CoverageGraphSnapshot } from './ScanCoverageGraph.types';

export interface UseCoverageGraphReturn {
    // State
    coverageGraph: CoverageGraphSnapshot | null;
    showEndpointIntelligence: boolean;
    showCoverageGraphFullscreen: boolean;
    scanTargetUrl: string | null;

    // Update callbacks (called from fetch functions)
    setCoverageGraph: (graph: CoverageGraphSnapshot | null) => void;
    setScanTargetUrl: (url: string | null) => void;

    // UI actions
    toggleEndpointIntelligence: () => void;
    openFullscreen: () => void;
    closeFullscreen: () => void;
}

export function useCoverageGraph(): UseCoverageGraphReturn {
    const [coverageGraph, setCoverageGraph] = useState<CoverageGraphSnapshot | null>(null);
    const [showEndpointIntelligence, setShowEndpointIntelligence] = useState(false);
    const [showCoverageGraphFullscreen, setShowCoverageGraphFullscreen] = useState(false);
    const [scanTargetUrl, setScanTargetUrl] = useState<string | null>(null);

    const toggleEndpointIntelligence = useCallback(() => {
        setShowEndpointIntelligence(prev => !prev);
    }, []);

    const openFullscreen = useCallback(() => {
        setShowCoverageGraphFullscreen(true);
    }, []);

    const closeFullscreen = useCallback(() => {
        setShowCoverageGraphFullscreen(false);
    }, []);

    return {
        coverageGraph,
        showEndpointIntelligence,
        showCoverageGraphFullscreen,
        scanTargetUrl,
        setCoverageGraph,
        setScanTargetUrl,
        toggleEndpointIntelligence,
        openFullscreen,
        closeFullscreen,
    };
}
