'use client';

import { useRef } from 'react';
import { motion } from 'framer-motion';
import { Zap, Brain, ChevronLeft, ChevronRight } from 'lucide-react';

export interface SourceMode {
    id: string;
    title: string;
    description: string[];
    tokenCost: 'low' | 'medium' | 'high';
    icon: 'zap' | 'brain';
}

interface SourceModeSelectorProps {
    modes: SourceMode[];
    selected: string | null;
    onSelect: (id: string) => void;
    disabled?: boolean;
}

const ICON_MAP = {
    zap: Zap,
    brain: Brain,
};

const TOKEN_COST_LABELS: Record<string, { label: string; color: string; bg: string }> = {
    low: { label: 'Low token cost', color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/30' },
    medium: { label: 'Medium token cost', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
    high: { label: 'High token cost', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30' },
};

export default function SourceModeSelector({ modes, selected, onSelect, disabled }: SourceModeSelectorProps) {
    const scrollRef = useRef<HTMLDivElement>(null);

    const scroll = (direction: 'left' | 'right') => {
        if (!scrollRef.current) return;
        const amount = 320;
        scrollRef.current.scrollBy({
            left: direction === 'left' ? -amount : amount,
            behavior: 'smooth',
        });
    };

    return (
        <div className="relative">
            <div className="flex items-center justify-between mb-3">
                <label className="text-gray-400 text-sm">Source Analysis Mode</label>
                <div className="flex gap-1">
                    <button
                        type="button"
                        onClick={() => scroll('left')}
                        className="p-1 rounded bg-dark-700 text-gray-400 hover:text-white transition-colors"
                        aria-label="Scroll left"
                    >
                        <ChevronLeft className="w-4 h-4" />
                    </button>
                    <button
                        type="button"
                        onClick={() => scroll('right')}
                        className="p-1 rounded bg-dark-700 text-gray-400 hover:text-white transition-colors"
                        aria-label="Scroll right"
                    >
                        <ChevronRight className="w-4 h-4" />
                    </button>
                </div>
            </div>

            <div
                ref={scrollRef}
                className="flex gap-4 overflow-x-auto pb-2 scroll-smooth"
                style={{
                    scrollSnapType: 'x mandatory',
                    WebkitOverflowScrolling: 'touch',
                    scrollbarWidth: 'none',
                    msOverflowStyle: 'none',
                }}
            >
                {modes.map((mode) => {
                    const isSelected = selected === mode.id;
                    const IconComponent = ICON_MAP[mode.icon] || Zap;
                    const cost = TOKEN_COST_LABELS[mode.tokenCost] || TOKEN_COST_LABELS.low;

                    return (
                        <motion.button
                            key={mode.id}
                            type="button"
                            disabled={disabled}
                            onClick={() => onSelect(mode.id)}
                            whileTap={{ scale: 0.98 }}
                            className={`
                                flex-shrink-0 w-72 p-5 rounded-xl border-2 text-left transition-all duration-200
                                ${isSelected
                                    ? 'border-cyan-500 bg-cyan-500/10 shadow-lg shadow-cyan-500/10'
                                    : 'border-dark-600 bg-dark-800/50 hover:border-dark-500 hover:bg-dark-800'
                                }
                                ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                            `}
                            style={{ scrollSnapAlign: 'start' }}
                        >
                            <div className="flex items-center gap-3 mb-3">
                                <div className={`
                                    w-10 h-10 rounded-lg flex items-center justify-center
                                    ${isSelected
                                        ? 'bg-cyan-500/20 border border-cyan-500/40'
                                        : 'bg-dark-700 border border-dark-600'
                                    }
                                `}>
                                    <IconComponent className={`w-5 h-5 ${isSelected ? 'text-cyan-400' : 'text-gray-400'}`} />
                                </div>
                                <div>
                                    <h4 className={`font-semibold text-sm ${isSelected ? 'text-white' : 'text-gray-300'}`}>
                                        {mode.title}
                                    </h4>
                                </div>
                            </div>

                            <ul className="space-y-1.5 mb-4">
                                {mode.description.map((desc, i) => (
                                    <li key={i} className="text-xs text-gray-400 flex items-start gap-2">
                                        <span className={`mt-1 w-1 h-1 rounded-full flex-shrink-0 ${isSelected ? 'bg-cyan-400' : 'bg-gray-600'}`} />
                                        {desc}
                                    </li>
                                ))}
                            </ul>

                            <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-xs ${cost.bg}`}>
                                <Zap className={`w-3 h-3 ${cost.color}`} />
                                <span className={cost.color}>{cost.label}</span>
                            </div>

                            {isSelected && (
                                <motion.div
                                    initial={{ opacity: 0, scale: 0.8 }}
                                    animate={{ opacity: 1, scale: 1 }}
                                    className="mt-3 text-xs text-cyan-400 font-medium"
                                >
                                    Selected
                                </motion.div>
                            )}
                        </motion.button>
                    );
                })}
            </div>

            {selected && modes.find(m => m.id === selected)?.tokenCost === 'high' && (
                <motion.div
                    initial={{ opacity: 0, y: -5 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mt-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-sm text-gray-300"
                >
                    <strong className="text-amber-400">Token notice:</strong>{' '}
                    Full Source Aware mode performs deep code analysis using the LLM. This significantly increases token usage.
                    Select this mode only when you intentionally want comprehensive source understanding.
                </motion.div>
            )}
        </div>
    );
}
