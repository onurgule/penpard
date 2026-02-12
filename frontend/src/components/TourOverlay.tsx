'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { X, ChevronLeft, ChevronRight, SkipForward } from 'lucide-react';
import { useTourStore, TourStep } from '@/lib/store/tour';

interface SpotlightPosition {
    top: number;
    left: number;
    width: number;
    height: number;
}

interface TooltipPosition {
    top: number;
    left: number;
}

export default function TourOverlay() {
    const router = useRouter();
    const pathname = usePathname();
    const {
        isActive,
        currentStepIndex,
        steps,
        nextStep,
        prevStep,
        skipTour,
        endTour,
    } = useTourStore();

    const [spotlight, setSpotlight] = useState<SpotlightPosition | null>(null);
    const [tooltipPos, setTooltipPos] = useState<TooltipPosition>({ top: 0, left: 0 });
    const [isNavigating, setIsNavigating] = useState(false);

    const currentStep: TourStep | undefined = steps[currentStepIndex];
    const isFirstStep = currentStepIndex === 0;
    const isLastStep = currentStepIndex === steps.length - 1;

    const updateSpotlight = useCallback(() => {
        if (!currentStep) return;

        const element = document.querySelector(currentStep.target);
        if (!element) {
            setSpotlight(null);
            return;
        }

        const rect = element.getBoundingClientRect();
        const padding = 8;

        const newSpotlight = {
            top: rect.top - padding,
            left: rect.left - padding,
            width: rect.width + padding * 2,
            height: rect.height + padding * 2,
        };

        setSpotlight(newSpotlight);

        // Calculate tooltip position based on placement
        const tooltipWidth = 320;
        const tooltipHeight = 180;
        const gap = 16;
        let top = 0;
        let left = 0;

        switch (currentStep.placement) {
            case 'top':
                top = newSpotlight.top - tooltipHeight - gap;
                left = newSpotlight.left + newSpotlight.width / 2 - tooltipWidth / 2;
                break;
            case 'bottom':
                top = newSpotlight.top + newSpotlight.height + gap;
                left = newSpotlight.left + newSpotlight.width / 2 - tooltipWidth / 2;
                break;
            case 'left':
                top = newSpotlight.top + newSpotlight.height / 2 - tooltipHeight / 2;
                left = newSpotlight.left - tooltipWidth - gap;
                break;
            case 'right':
                top = newSpotlight.top + newSpotlight.height / 2 - tooltipHeight / 2;
                left = newSpotlight.left + newSpotlight.width + gap;
                break;
            default:
                top = newSpotlight.top + newSpotlight.height + gap;
                left = newSpotlight.left + newSpotlight.width / 2 - tooltipWidth / 2;
        }

        // Keep tooltip within viewport
        const viewportPadding = 20;
        top = Math.max(viewportPadding, Math.min(top, window.innerHeight - tooltipHeight - viewportPadding));
        left = Math.max(viewportPadding, Math.min(left, window.innerWidth - tooltipWidth - viewportPadding));

        setTooltipPos({ top, left });
    }, [currentStep]);

    // Handle navigation between steps that require route changes
    useEffect(() => {
        if (!isActive || !currentStep) return;

        if (currentStep.route && pathname !== currentStep.route) {
            setIsNavigating(true);
            router.push(currentStep.route);
        } else {
            setIsNavigating(false);
        }
    }, [isActive, currentStep, pathname, router]);

    // Update spotlight when step changes or navigation completes
    useEffect(() => {
        if (!isActive || isNavigating) return;

        // Wait for DOM to settle after navigation
        const timeout = setTimeout(() => {
            updateSpotlight();
        }, 300);

        return () => clearTimeout(timeout);
    }, [isActive, currentStepIndex, isNavigating, pathname, updateSpotlight]);

    // Update spotlight on resize
    useEffect(() => {
        if (!isActive) return;

        const handleResize = () => updateSpotlight();
        window.addEventListener('resize', handleResize);
        return () => window.removeEventListener('resize', handleResize);
    }, [isActive, updateSpotlight]);

    // Handle keyboard navigation
    useEffect(() => {
        if (!isActive) return;

        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                skipTour();
            } else if (e.key === 'ArrowRight' || e.key === 'Enter') {
                if (isLastStep) {
                    endTour();
                } else {
                    nextStep();
                }
            } else if (e.key === 'ArrowLeft') {
                prevStep();
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [isActive, isLastStep, nextStep, prevStep, skipTour, endTour]);

    if (!isActive || !currentStep) return null;

    return (
        <AnimatePresence>
            <div className="fixed inset-0 z-[9999] pointer-events-none">
                {/* Dark overlay with spotlight cutout */}
                <svg className="absolute inset-0 w-full h-full pointer-events-auto">
                    <defs>
                        <mask id="spotlight-mask">
                            <rect x="0" y="0" width="100%" height="100%" fill="white" />
                            {spotlight && (
                                <motion.rect
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    x={spotlight.left}
                                    y={spotlight.top}
                                    width={spotlight.width}
                                    height={spotlight.height}
                                    rx="8"
                                    fill="black"
                                />
                            )}
                        </mask>
                    </defs>
                    <rect
                        x="0"
                        y="0"
                        width="100%"
                        height="100%"
                        fill="rgba(0, 0, 0, 0.75)"
                        mask="url(#spotlight-mask)"
                    />
                </svg>

                {/* Spotlight border glow */}
                {spotlight && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        className="absolute rounded-lg pointer-events-none"
                        style={{
                            top: spotlight.top,
                            left: spotlight.left,
                            width: spotlight.width,
                            height: spotlight.height,
                            boxShadow: '0 0 0 4px rgba(34, 211, 238, 0.5), 0 0 20px rgba(34, 211, 238, 0.3)',
                        }}
                    />
                )}

                {/* Tooltip */}
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    transition={{ duration: 0.2 }}
                    className="absolute w-80 glass rounded-xl p-5 pointer-events-auto"
                    style={{
                        top: tooltipPos.top,
                        left: tooltipPos.left,
                        boxShadow: '0 0 30px rgba(34, 211, 238, 0.2)',
                    }}
                >
                    {/* Close button */}
                    <button
                        onClick={skipTour}
                        className="absolute top-3 right-3 text-gray-400 hover:text-white transition-colors"
                        title="Close tour (Esc)"
                    >
                        <X className="w-5 h-5" />
                    </button>

                    {/* Step indicator */}
                    <div className="flex items-center gap-1 mb-3">
                        {steps.map((_, idx) => (
                            <div
                                key={idx}
                                className={`h-1 rounded-full transition-all ${
                                    idx === currentStepIndex
                                        ? 'w-6 bg-cyan-400'
                                        : idx < currentStepIndex
                                        ? 'w-2 bg-cyan-600'
                                        : 'w-2 bg-gray-600'
                                }`}
                            />
                        ))}
                    </div>

                    {/* Content */}
                    <h3 className="text-lg font-semibold text-white mb-2">
                        {currentStep.title}
                    </h3>
                    <p className="text-gray-300 text-sm leading-relaxed mb-4">
                        {currentStep.content}
                    </p>

                    {/* Navigation buttons */}
                    <div className="flex items-center justify-between">
                        <button
                            onClick={skipTour}
                            className="flex items-center gap-1 text-gray-400 hover:text-white text-sm transition-colors"
                        >
                            <SkipForward className="w-4 h-4" />
                            Skip tour
                        </button>

                        <div className="flex items-center gap-2">
                            {!isFirstStep && (
                                <button
                                    onClick={prevStep}
                                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-dark-600 hover:bg-dark-500 text-gray-300 text-sm transition-colors"
                                >
                                    <ChevronLeft className="w-4 h-4" />
                                    Back
                                </button>
                            )}
                            <button
                                onClick={isLastStep ? endTour : nextStep}
                                className="flex items-center gap-1 px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-medium text-sm transition-colors"
                            >
                                {isLastStep ? 'Finish' : 'Next'}
                                {!isLastStep && <ChevronRight className="w-4 h-4" />}
                            </button>
                        </div>
                    </div>

                    {/* Keyboard hint */}
                    <p className="text-gray-500 text-xs mt-3 text-center">
                        Use arrow keys to navigate, Esc to close
                    </p>
                </motion.div>
            </div>
        </AnimatePresence>
    );
}
