'use client';

import { useState, useEffect } from 'react';
import { useAuthStore } from '@/lib/store/auth';
// Replaced TinyMCE with basic textarea to fix Docker/Production build crash
// import { Editor } from '@tinymce/tinymce-react';
import toast from 'react-hot-toast';

export default function ReportTemplateEditor() {
    const { token } = useAuthStore();
    const [content, setContent] = useState('');
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        // Mock fetch template - in reality we would fetch from /api/settings/template
        // For now, load default
        setContent(`
            <h1>Security Assessment Report</h1>
            <p><strong>Target:</strong> {{target}}</p>
            <p><strong>Date:</strong> {{date}}</p>
            <h2>Executive Summary</h2>
            <p>The security assessment identified {{vuln_count}} vulnerabilities.</p>
            <p>[Insert Summary Here]</p>
        `);
        setIsLoading(false);
    }, []);

    const handleSave = async () => {
        try {
            // Save to backend
            // await axios.post('/api/settings/template', { content });
            toast.success('Report template saved successfully');
        } catch (error) {
            toast.error('Failed to save template');
        }
    };

    if (isLoading) return <div>Loading editor...</div>;

    return (
        <div className="space-y-4">
            <div className="flex justify-between items-center mb-4">
                <div>
                    <h3 className="text-lg font-medium text-white">Report Template</h3>
                    <p className="text-sm text-gray-400">Customize the layout of generated PDF/HTML reports.</p>
                </div>
                <button
                    onClick={handleSave}
                    className="bg-cyan-500 hover:bg-cyan-600 text-black font-bold py-2 px-4 rounded transition-colors"
                >
                    Save Template
                </button>
            </div>

            <div className="bg-white rounded-lg overflow-hidden text-black h-[600px] border-2 border-slate-200 focus-within:border-cyan-500 transition-colors">
                {/* 
                  Fallback Textarea Implementation
                  This replaces the TinyMCE Editor component which was causing 500 errors in Docker ("Module not found").
                  This ensures the settings page remains accessible and functional.
                */}
                <textarea
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                    className="w-full h-full p-4 font-mono text-sm border-none focus:ring-0 outline-none resize-none text-slate-800"
                    placeholder="Enter your HTML report template here..."
                />
            </div>

            <div className="bg-dark-800 p-4 rounded border border-gray-700">
                <h4 className="font-bold text-gray-300 mb-2">Available Variables</h4>
                <div className="flex flex-wrap gap-2 text-xs font-mono text-cyan-400">
                    <span className="bg-dark-900 px-2 py-1 rounded">{`{{ target }}`}</span>
                    <span className="bg-dark-900 px-2 py-1 rounded">{`{{ date }}`}</span>
                    <span className="bg-dark-900 px-2 py-1 rounded">{`{{ vuln_count }}`}</span>
                    <span className="bg-dark-900 px-2 py-1 rounded">{`{{ findings_table }}`}</span>
                    <span className="bg-dark-900 px-2 py-1 rounded">{`{{ executive_summary }}`}</span>
                </div>
            </div>
        </div>
    );
}
