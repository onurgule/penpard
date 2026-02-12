'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { Eye, EyeOff, Lock, AlertTriangle } from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import toast from 'react-hot-toast';

export default function LockScreenPage() {
    const router = useRouter();
    const { unlock, isLoading, error, isAuthenticated } = useAuthStore();

    const [key, setKey] = useState('');
    const [showKey, setShowKey] = useState(false);
    const [typingPhase, setTypingPhase] = useState(0);

    // Redirect if already authenticated
    useEffect(() => {
        if (isAuthenticated) {
            router.push('/dashboard');
        }
    }, [isAuthenticated, router]);

    // Typing animation for tagline
    useEffect(() => {
        const timer = setInterval(() => {
            setTypingPhase((prev) => (prev + 1) % 4);
        }, 3000);
        return () => clearInterval(timer);
    }, []);

    const taglines = [
        'IDENTIFYING THREATS...',
        'ANALYZING VULNERABILITIES...',
        'SECURING SYSTEMS...',
        'AWAITING AUTHORIZATION...',
    ];

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!key) {
            toast.error('Please enter the lock key');
            return;
        }

        try {
            await unlock(key);
            toast.success('Access granted');
            router.push('/dashboard');
        } catch (err) {
            toast.error('Invalid key');
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center px-4 relative overflow-hidden">
            {/* Background effects */}
            <div className="absolute inset-0">
                <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-[100px]" />
                <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-[100px]" />
            </div>

            {/* Lock Card */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, ease: 'easeOut' }}
                className="relative z-10 w-full max-w-md"
            >
                <div className="glass rounded-2xl p-8 glow-cyan">
                    {/* Logo / Title */}
                    <div className="text-center mb-8">
                        <motion.div
                            initial={{ scale: 0.8 }}
                            animate={{ scale: 1 }}
                            transition={{ duration: 0.5, delay: 0.2 }}
                            className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 mb-4 glow-cyan-strong"
                        >
                            <Lock className="w-10 h-10 text-white" />
                        </motion.div>

                        <motion.h1
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            transition={{ delay: 0.3 }}
                            className="text-3xl font-bold text-white mb-2 tracking-tight"
                        >
                            PENPARD
                        </motion.h1>

                        <motion.p
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            transition={{ delay: 0.4 }}
                            className="terminal-text text-cyan-400 text-sm h-6"
                        >
                            {taglines[typingPhase]}
                            <span className="animate-pulse">_</span>
                        </motion.p>
                    </div>

                    {/* Error Message */}
                    {error && (
                        <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            className="mb-6 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-2"
                        >
                            <AlertTriangle className="w-5 h-5 text-red-400" />
                            <span className="text-red-400 text-sm">{error}</span>
                        </motion.div>
                    )}

                    {/* Lock Key Form */}
                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div>
                            <label className="block text-gray-400 text-sm font-medium mb-2">
                                LOCK KEY
                            </label>
                            <div className="relative">
                                <input
                                    type={showKey ? 'text' : 'password'}
                                    value={key}
                                    onChange={(e) => setKey(e.target.value)}
                                    className="input-field terminal-text pr-12"
                                    placeholder="Enter lock key"
                                    autoComplete="current-password"
                                    disabled={isLoading}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowKey(!showKey)}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-cyan-400 transition-colors"
                                >
                                    {showKey ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                                </button>
                            </div>
                        </div>

                        <motion.button
                            type="submit"
                            disabled={isLoading}
                            whileHover={{ scale: isLoading ? 1 : 1.02 }}
                            whileTap={{ scale: isLoading ? 1 : 0.98 }}
                            className="w-full btn-primary flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {isLoading ? (
                                <>
                                    <div className="spinner" />
                                    <span>VERIFYING...</span>
                                </>
                            ) : (
                                <>
                                    <Lock className="w-5 h-5" />
                                    <span>UNLOCK</span>
                                </>
                            )}
                        </motion.button>
                    </form>

                    {/* Footer */}
                    <div className="mt-8 pt-6 border-t border-dark-600/50 text-center">
                        <p className="text-gray-500 text-xs terminal-text">
                            SYSTEM v1.0.1 • LOCAL INSTANCE
                        </p>
                        <p className="text-gray-600 text-xs mt-1">
                            Unauthorized access is prohibited
                        </p>
                    </div>
                </div>
            </motion.div>
        </div>
    );
}
