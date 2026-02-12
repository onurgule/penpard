'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion } from 'framer-motion';
import {
    ArrowLeft,
    FileText,
    Save,
    RotateCcw,
    AlertCircle,
    CheckCircle,
    Upload,
    Image as ImageIcon,
    BookOpen,
} from 'lucide-react';
import { useAuthStore } from '@/lib/store/auth';
import axios from 'axios';
import toast from 'react-hot-toast';
import { API_URL } from '@/lib/api-config';

interface PromptConfig {
    id: string;
    name: string;
    key: string;
    description: string;
    template: string;
    variables: string[];
}

const DEFAULT_PROMPTS: PromptConfig[] = [
    {
        id: 'web_pentest',
        name: 'Web Penetration Test',
        key: 'web_prompt',
        description: 'Main prompt for web application security testing',
        template: `You are an expert penetration tester conducting an authorized security assessment.

TARGET: {TARGET_WEBSITE}
SCOPE: This is a whitelisted, fully authorized ethical penetration test.

Your objectives:
1. Identify OWASP Top 10 vulnerabilities
2. Test for SQL Injection (SQLi) in all input points
3. Test for Cross-Site Scripting (XSS) - reflected, stored, DOM-based
4. Check for IDOR (Insecure Direct Object References)
5. Test authentication and authorization mechanisms
6. Look for sensitive data exposure
7. Check for security misconfigurations

TEST ACCOUNTS (for IDOR testing):
{TARGET_WEBSITE_ACCOUNTS}

METHODOLOGY:
- Start with reconnaissance and endpoint discovery
- Map all parameters and input points
- MAX 2-3 payloads per vuln type per parameter - do NOT brute-force
- If basic payloads don't confirm vuln → use send_to_scanner (Burp Scanner does deep testing)
- NEVER do SQLMap-style UNION SELECT null,null,null... enumeration - use send_to_scanner instead

Tools: send_http_request, send_to_scanner, get_proxy_history`,
        variables: ['TARGET_WEBSITE', 'TARGET_WEBSITE_ACCOUNTS']
    },
    {
        id: 'api_pentest',
        name: 'API Security Test',
        key: 'api_prompt',
        description: 'Prompt for REST/GraphQL API security testing',
        template: `You are conducting an authorized API security assessment.

TARGET API: {TARGET_API}
AUTHENTICATION: {AUTH_TYPE}

Test for:
1. Broken Authentication (JWT issues, session management)
2. Broken Authorization (BOLA/IDOR)
3. Excessive Data Exposure
4. Lack of Rate Limiting
5. Mass Assignment vulnerabilities
6. SQL/NoSQL Injection
7. SSRF vulnerabilities

API Credentials:
{API_CREDENTIALS}

Analyze each endpoint methodically and report findings.`,
        variables: ['TARGET_API', 'AUTH_TYPE', 'API_CREDENTIALS']
    },
    {
        id: 'sqli_focus',
        name: 'SQL Injection Focus',
        key: 'sqli_prompt',
        description: 'Specialized prompt for SQL injection testing',
        template: `Focus specifically on SQL Injection testing for {TARGET_ENDPOINT}.

Test vectors (MAX 2-3 per param - do NOT enumerate column count manually):
- Error-based: ', ' OR '1'='1
- Boolean: ' AND '1'='1 vs ' AND '1'='2
- If no SQL error → use send_to_scanner with the URL (Burp Scanner handles UNION/time-based)

Database hints: {DATABASE_TYPE}

NEVER send UNION SELECT null,null,null,null... with varying null counts - use send_to_scanner instead.`,
        variables: ['TARGET_ENDPOINT', 'DATABASE_TYPE']
    },
    {
        id: 'idor_check',
        name: 'IDOR/Authorization Check',
        key: 'idor_prompt',
        description: 'Prompt for testing authorization bypasses',
        template: `Perform IDOR and authorization testing on {TARGET_ENDPOINT}.

User Accounts for Testing:
{USER_ACCOUNTS}

Steps:
1. Capture a request as User A accessing their own resource
2. Identify the resource identifier (ID, UUID, etc)
3. Replay the same request with User B's credentials
4. Compare responses - can User B access User A's data?
5. Also test:
   - Horizontal privilege escalation (user to user)
   - Vertical privilege escalation (user to admin)
   - Unauthenticated access to protected resources

Report any access control failures with full evidence.`,
        variables: ['TARGET_ENDPOINT', 'USER_ACCOUNTS']
    }
];

export default function PromptsPage() {
    const router = useRouter();
    const { token, isAuthenticated } = useAuthStore();
    const [prompts, setPrompts] = useState<PromptConfig[]>(DEFAULT_PROMPTS);
    const [selectedPrompt, setSelectedPrompt] = useState<PromptConfig | null>(null);
    const [editedTemplate, setEditedTemplate] = useState('');
    const [saving, setSaving] = useState(false);
    const [logoFile, setLogoFile] = useState<File | null>(null);
    const [logoPreview, setLogoPreview] = useState<string | null>(null);

    // Auth guard
    useEffect(() => {
        if (!isAuthenticated) {
            router.push('/');
        }
    }, [isAuthenticated, router]);

    useEffect(() => {
        if (isAuthenticated) {
            loadPrompts();
            loadLogo();
        }
    }, [isAuthenticated]);

    const loadPrompts = async () => {
        try {
            const res = await axios.get(`${API_URL}/config/prompts`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.data.prompts && res.data.prompts.length > 0) {
                setPrompts(res.data.prompts);
            }
        } catch (e) {
            // Use defaults if not saved yet
        }
    };

    const loadLogo = async () => {
        try {
            const res = await axios.get(`${API_URL}/config/logo`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.data.logoUrl) {
                setLogoPreview(res.data.logoUrl);
            }
        } catch (e) {
            // No logo set
        }
    };

    const handleSelectPrompt = (prompt: PromptConfig) => {
        setSelectedPrompt(prompt);
        setEditedTemplate(prompt.template);
    };

    const handleSavePrompt = async () => {
        if (!selectedPrompt) return;

        setSaving(true);
        try {
            const updatedPrompts = prompts.map(p =>
                p.id === selectedPrompt.id
                    ? { ...p, template: editedTemplate }
                    : p
            );

            await axios.post(`${API_URL}/config/prompts`,
                { prompts: updatedPrompts },
                { headers: { Authorization: `Bearer ${token}` } }
            );

            setPrompts(updatedPrompts);
            toast.success('Prompt saved successfully');
        } catch (e) {
            toast.error('Failed to save prompt');
        } finally {
            setSaving(false);
        }
    };

    const handleResetPrompt = () => {
        if (!selectedPrompt) return;
        const original = DEFAULT_PROMPTS.find(p => p.id === selectedPrompt.id);
        if (original) {
            setEditedTemplate(original.template);
            toast.success('Reset to default');
        }
    };

    const handleLogoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;

        // Preview
        const reader = new FileReader();
        reader.onload = (ev) => {
            setLogoPreview(ev.target?.result as string);
        };
        reader.readAsDataURL(file);
        setLogoFile(file);

        // Upload
        const formData = new FormData();
        formData.append('logo', file);

        try {
            await axios.post(`${API_URL}/config/logo`, formData, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'multipart/form-data'
                }
            });
            toast.success('Logo uploaded successfully');
        } catch (e) {
            toast.error('Failed to upload logo');
        }
    };

    if (!isAuthenticated) return null;

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100">
            <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-10 z-40">
                <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
                    <Link href="/settings" className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors">
                        <ArrowLeft className="w-5 h-5" />
                        <span>Settings</span>
                    </Link>
                    <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent flex items-center gap-2">
                        <FileText className="w-5 h-5 text-cyan-400" />
                        Prompt Templates
                    </h1>
                    <Link
                        href="/settings/prompt-library"
                        className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500/10 to-blue-500/10 hover:from-cyan-500/20 hover:to-blue-500/20 text-cyan-400 text-xs font-bold transition-colors flex items-center gap-1.5 border border-cyan-500/30"
                    >
                        <BookOpen className="w-3.5 h-3.5" />
                        Prompt Library
                    </Link>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-4 py-8 grid grid-cols-12 gap-6">
                {/* Left: Prompt List + Logo */}
                <div className="col-span-12 lg:col-span-4 space-y-6">
                    {/* Logo Upload */}
                    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                            <ImageIcon className="w-4 h-4" />
                            Report Logo
                        </h2>
                        <p className="text-xs text-slate-500 mb-4">
                            Upload your company logo to include in PDF reports.
                        </p>

                        <div className="flex items-center gap-4">
                            {logoPreview ? (
                                <div className="w-20 h-20 rounded-lg border border-slate-700 overflow-hidden bg-white flex items-center justify-center">
                                    <img src={logoPreview} alt="Logo" className="max-w-full max-h-full object-contain" />
                                </div>
                            ) : (
                                <div className="w-20 h-20 rounded-lg border border-dashed border-slate-700 flex items-center justify-center text-slate-600">
                                    <ImageIcon className="w-8 h-8" />
                                </div>
                            )}

                            <label className="cursor-pointer">
                                <input
                                    type="file"
                                    accept="image/*"
                                    onChange={handleLogoUpload}
                                    className="hidden"
                                />
                                <span className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
                                    <Upload className="w-4 h-4" />
                                    Upload
                                </span>
                            </label>
                        </div>
                    </div>

                    {/* Prompt List */}
                    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4">
                            Available Prompts
                        </h2>
                        <div className="space-y-2">
                            {prompts.map(prompt => (
                                <button
                                    key={prompt.id}
                                    onClick={() => handleSelectPrompt(prompt)}
                                    className={`w-full text-left p-3 rounded-lg border transition-all ${selectedPrompt?.id === prompt.id
                                            ? 'bg-cyan-500/10 border-cyan-500/50'
                                            : 'bg-slate-800/50 border-slate-700 hover:border-slate-600'
                                        }`}
                                >
                                    <div className="font-medium text-sm">{prompt.name}</div>
                                    <div className="text-xs text-slate-500 mt-1">{prompt.description}</div>
                                    <div className="flex gap-1 mt-2 flex-wrap">
                                        {prompt.variables.map(v => (
                                            <span key={v} className="text-[10px] px-1.5 py-0.5 bg-slate-700 rounded text-slate-400">
                                                {'{' + v + '}'}
                                            </span>
                                        ))}
                                    </div>
                                </button>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Right: Editor */}
                <div className="col-span-12 lg:col-span-8">
                    {selectedPrompt ? (
                        <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
                            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-800/50">
                                <div>
                                    <h3 className="font-bold">{selectedPrompt.name}</h3>
                                    <p className="text-xs text-slate-500">{selectedPrompt.key}</p>
                                </div>
                                <div className="flex gap-2">
                                    <button
                                        onClick={handleResetPrompt}
                                        className="px-3 py-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-sm font-medium transition-colors flex items-center gap-1.5"
                                    >
                                        <RotateCcw className="w-3.5 h-3.5" />
                                        Reset
                                    </button>
                                    <button
                                        onClick={handleSavePrompt}
                                        disabled={saving}
                                        className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-sm font-bold transition-colors flex items-center gap-1.5 disabled:opacity-50"
                                    >
                                        <Save className="w-3.5 h-3.5" />
                                        {saving ? 'Saving...' : 'Save'}
                                    </button>
                                </div>
                            </div>

                            <div className="p-4">
                                <label className="text-xs uppercase text-slate-500 font-bold tracking-wider mb-2 block">
                                    Template Content
                                </label>
                                <textarea
                                    value={editedTemplate}
                                    onChange={e => setEditedTemplate(e.target.value)}
                                    rows={20}
                                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-4 font-mono text-sm text-slate-300 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all resize-none"
                                    placeholder="Enter your prompt template..."
                                />

                                <div className="mt-4 p-3 bg-slate-800/50 rounded-lg">
                                    <div className="text-xs font-bold text-slate-400 mb-2 flex items-center gap-1.5">
                                        <AlertCircle className="w-3.5 h-3.5" />
                                        Available Variables
                                    </div>
                                    <div className="flex gap-2 flex-wrap">
                                        {selectedPrompt.variables.map(v => (
                                            <code key={v} className="text-xs px-2 py-1 bg-slate-900 rounded text-cyan-400 border border-slate-700">
                                                {'{' + v + '}'}
                                            </code>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-12 text-center">
                            <FileText className="w-12 h-12 text-slate-700 mx-auto mb-4" />
                            <p className="text-slate-500">Select a prompt template to edit</p>
                        </div>
                    )}
                </div>
            </main>
        </div>
    );
}
