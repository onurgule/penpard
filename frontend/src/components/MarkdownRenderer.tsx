'use client';

import React from 'react';

interface MarkdownRendererProps {
    content: string;
    className?: string;
}

/**
 * Simple Markdown renderer that handles common markdown syntax
 * without external dependencies
 */
export function MarkdownRenderer({ content, className = '' }: MarkdownRendererProps) {
    const renderMarkdown = (text: string): React.ReactNode[] => {
        const lines = text.split('\n');
        const elements: React.ReactNode[] = [];
        let listItems: string[] = [];
        let listType: 'ul' | 'ol' | null = null;
        let codeBlock: string[] = [];
        let inCodeBlock = false;

        const flushList = () => {
            if (listItems.length > 0) {
                const ListTag = listType === 'ol' ? 'ol' : 'ul';
                elements.push(
                    <ListTag key={elements.length} className={listType === 'ol' ? 'list-decimal pl-6 mb-3 space-y-1' : 'list-disc pl-6 mb-3 space-y-1'}>
                        {listItems.map((item, i) => (
                            <li key={i} className="text-slate-300">{renderInline(item)}</li>
                        ))}
                    </ListTag>
                );
                listItems = [];
                listType = null;
            }
        };

        const flushCodeBlock = () => {
            if (codeBlock.length > 0) {
                elements.push(
                    <pre key={elements.length} className="bg-black/50 p-4 rounded-lg overflow-x-auto my-3 text-xs font-mono text-green-400 border border-white/10">
                        <code>{codeBlock.join('\n')}</code>
                    </pre>
                );
                codeBlock = [];
            }
        };

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            // Code block
            if (line.startsWith('```')) {
                if (inCodeBlock) {
                    flushCodeBlock();
                    inCodeBlock = false;
                } else {
                    flushList();
                    inCodeBlock = true;
                }
                continue;
            }

            if (inCodeBlock) {
                codeBlock.push(line);
                continue;
            }

            // Headers
            if (line.startsWith('### ')) {
                flushList();
                elements.push(<h3 key={elements.length} className="text-sm font-bold text-white mb-2 mt-3">{renderInline(line.slice(4))}</h3>);
                continue;
            }
            if (line.startsWith('## ')) {
                flushList();
                elements.push(<h2 key={elements.length} className="text-base font-bold text-white mb-2 mt-4">{renderInline(line.slice(3))}</h2>);
                continue;
            }
            if (line.startsWith('# ')) {
                flushList();
                elements.push(<h1 key={elements.length} className="text-lg font-bold text-white mb-3 mt-4">{renderInline(line.slice(2))}</h1>);
                continue;
            }

            // Unordered list
            if (line.match(/^[\-\*]\s/)) {
                if (listType !== 'ul') {
                    flushList();
                    listType = 'ul';
                }
                listItems.push(line.slice(2));
                continue;
            }

            // Ordered list
            if (line.match(/^\d+\.\s/)) {
                if (listType !== 'ol') {
                    flushList();
                    listType = 'ol';
                }
                listItems.push(line.replace(/^\d+\.\s/, ''));
                continue;
            }

            // Empty line
            if (line.trim() === '') {
                flushList();
                continue;
            }

            // Regular paragraph
            flushList();
            elements.push(<p key={elements.length} className="mb-2 text-slate-300 leading-relaxed">{renderInline(line)}</p>);
        }

        flushList();
        flushCodeBlock();

        return elements;
    };

    const renderInline = (text: string): React.ReactNode => {
        // Process inline elements: bold, italic, code, links
        const parts: React.ReactNode[] = [];
        let remaining = text;
        let key = 0;

        while (remaining.length > 0) {
            // Inline code
            const codeMatch = remaining.match(/`([^`]+)`/);
            if (codeMatch && codeMatch.index !== undefined) {
                if (codeMatch.index > 0) {
                    parts.push(processEmphasis(remaining.slice(0, codeMatch.index), key++));
                }
                parts.push(
                    <code key={key++} className="bg-black/40 px-1.5 py-0.5 rounded text-cyan-400 text-xs font-mono">
                        {codeMatch[1]}
                    </code>
                );
                remaining = remaining.slice(codeMatch.index + codeMatch[0].length);
                continue;
            }

            // Link
            const linkMatch = remaining.match(/\[([^\]]+)\]\(([^)]+)\)/);
            if (linkMatch && linkMatch.index !== undefined) {
                if (linkMatch.index > 0) {
                    parts.push(processEmphasis(remaining.slice(0, linkMatch.index), key++));
                }
                parts.push(
                    <a key={key++} href={linkMatch[2]} target="_blank" rel="noopener noreferrer" className="text-cyan-400 underline hover:text-cyan-300">
                        {linkMatch[1]}
                    </a>
                );
                remaining = remaining.slice(linkMatch.index + linkMatch[0].length);
                continue;
            }

            // No more special patterns, process emphasis and add remaining
            parts.push(processEmphasis(remaining, key++));
            break;
        }

        return parts.length === 1 ? parts[0] : <>{parts}</>;
    };

    const processEmphasis = (text: string, keyBase: number): React.ReactNode => {
        // Bold **text**
        const parts: React.ReactNode[] = [];
        const boldRegex = /\*\*([^*]+)\*\*/g;
        let lastIndex = 0;
        let match;

        while ((match = boldRegex.exec(text)) !== null) {
            if (match.index > lastIndex) {
                parts.push(processItalic(text.slice(lastIndex, match.index), keyBase));
            }
            parts.push(<strong key={`${keyBase}-b-${match.index}`} className="text-white font-semibold">{match[1]}</strong>);
            lastIndex = match.index + match[0].length;
        }

        if (lastIndex < text.length) {
            parts.push(processItalic(text.slice(lastIndex), keyBase));
        }

        return parts.length === 1 ? parts[0] : <>{parts}</>;
    };

    const processItalic = (text: string, keyBase: number): React.ReactNode => {
        // Italic *text* or _text_
        const parts: React.ReactNode[] = [];
        const italicRegex = /(?:\*([^*]+)\*|_([^_]+)_)/g;
        let lastIndex = 0;
        let match;

        while ((match = italicRegex.exec(text)) !== null) {
            if (match.index > lastIndex) {
                parts.push(text.slice(lastIndex, match.index));
            }
            parts.push(<em key={`${keyBase}-i-${match.index}`} className="italic">{match[1] || match[2]}</em>);
            lastIndex = match.index + match[0].length;
        }

        if (lastIndex < text.length) {
            parts.push(text.slice(lastIndex));
        }

        return parts.length === 0 ? text : parts.length === 1 ? parts[0] : <>{parts}</>;
    };

    return (
        <div className={`prose prose-invert prose-sm max-w-none ${className}`}>
            {renderMarkdown(content)}
        </div>
    );
}

export default MarkdownRenderer;
