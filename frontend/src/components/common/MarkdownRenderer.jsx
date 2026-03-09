import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Copy, Check } from 'lucide-react';

/**
 * Industry-standard Markdown renderer for LLM responses.
 * Renders markdown with syntax highlighting, tables, lists, 
 * code blocks with copy buttons, and styled inline elements.
 * 
 * Matches the look and feel of Claude, ChatGPT, and Gemini responses.
 */
const MarkdownRenderer = ({ content, className = '' }) => {
    const [copiedBlock, setCopiedBlock] = useState(null);

    const handleCopy = (code, index) => {
        navigator.clipboard.writeText(code);
        setCopiedBlock(index);
        setTimeout(() => setCopiedBlock(null), 2000);
    };

    let codeBlockIndex = 0;

    return (
        <div className={`markdown-body ${className}`}>
            <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                    // ═══ HEADINGS ═══
                    h1: ({ children }) => (
                        <h1 className="text-xl font-bold text-white mt-5 mb-3 pb-2 border-b border-gray-700/50">
                            {children}
                        </h1>
                    ),
                    h2: ({ children }) => (
                        <h2 className="text-lg font-bold text-white mt-4 mb-2 pb-1.5 border-b border-gray-700/30">
                            {children}
                        </h2>
                    ),
                    h3: ({ children }) => (
                        <h3 className="text-base font-semibold text-white mt-3 mb-1.5">{children}</h3>
                    ),
                    h4: ({ children }) => (
                        <h4 className="text-sm font-semibold text-gray-200 mt-2 mb-1">{children}</h4>
                    ),

                    // ═══ PARAGRAPHS ═══
                    p: ({ children }) => (
                        <p className="text-gray-300 leading-relaxed mb-3 last:mb-0">{children}</p>
                    ),

                    // ═══ BOLD / ITALIC / STRIKETHROUGH ═══
                    strong: ({ children }) => (
                        <strong className="font-bold text-white">{children}</strong>
                    ),
                    em: ({ children }) => (
                        <em className="italic text-gray-200">{children}</em>
                    ),
                    del: ({ children }) => (
                        <del className="line-through text-gray-500">{children}</del>
                    ),

                    // ═══ LISTS ═══
                    ul: ({ children }) => (
                        <ul className="list-none space-y-1.5 mb-3 ml-1">{children}</ul>
                    ),
                    ol: ({ children }) => (
                        <ol className="list-decimal list-outside space-y-1.5 mb-3 ml-5 marker:text-indigo-400 marker:font-bold">
                            {children}
                        </ol>
                    ),
                    li: ({ children, ordered }) => (
                        <li className="text-gray-300 leading-relaxed flex gap-2">
                            {!ordered && (
                                <span className="text-indigo-400 mt-1.5 shrink-0">•</span>
                            )}
                            <span className="flex-1">{children}</span>
                        </li>
                    ),

                    // ═══ CODE (inline + block) ═══
                    code: ({ node, inline, className: langClass, children, ...props }) => {
                        const match = /language-(\w+)/.exec(langClass || '');
                        const codeString = String(children).replace(/\n$/, '');

                        if (!inline && (match || codeString.includes('\n'))) {
                            const currentIndex = codeBlockIndex++;
                            const language = match ? match[1] : 'text';

                            return (
                                <div className="relative group my-3 rounded-xl overflow-hidden border border-gray-700/50 shadow-lg">
                                    {/* Language label + copy button */}
                                    <div className="flex items-center justify-between bg-gray-800/80 px-4 py-2 border-b border-gray-700/50">
                                        <span className="text-xs font-mono text-gray-400 uppercase tracking-wider">
                                            {language}
                                        </span>
                                        <button
                                            onClick={() => handleCopy(codeString, currentIndex)}
                                            className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white transition-colors px-2 py-1 rounded hover:bg-white/10"
                                        >
                                            {copiedBlock === currentIndex ? (
                                                <><Check size={14} className="text-green-400" /> Copied!</>
                                            ) : (
                                                <><Copy size={14} /> Copy</>
                                            )}
                                        </button>
                                    </div>
                                    <SyntaxHighlighter
                                        style={oneDark}
                                        language={language}
                                        PreTag="div"
                                        customStyle={{
                                            margin: 0,
                                            padding: '1rem 1.25rem',
                                            background: 'rgba(0, 0, 0, 0.4)',
                                            fontSize: '0.8125rem',
                                            lineHeight: '1.6',
                                        }}
                                        {...props}
                                    >
                                        {codeString}
                                    </SyntaxHighlighter>
                                </div>
                            );
                        }

                        // Inline code
                        return (
                            <code className="px-1.5 py-0.5 bg-gray-700/60 text-indigo-300 rounded text-[0.85em] font-mono border border-gray-600/30" {...props}>
                                {children}
                            </code>
                        );
                    },

                    // ═══ LINKS ═══
                    a: ({ href, children }) => (
                        <a
                            href={href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-indigo-400 hover:text-indigo-300 underline underline-offset-2 decoration-indigo-400/30 hover:decoration-indigo-300/60 transition-colors"
                        >
                            {children}
                        </a>
                    ),

                    // ═══ BLOCKQUOTES ═══
                    blockquote: ({ children }) => (
                        <blockquote className="border-l-4 border-indigo-500/50 pl-4 py-1 my-3 bg-indigo-500/5 rounded-r-lg italic text-gray-300">
                            {children}
                        </blockquote>
                    ),

                    // ═══ HORIZONTAL RULE ═══
                    hr: () => (
                        <hr className="border-gray-700/50 my-4" />
                    ),

                    // ═══ TABLES ═══
                    table: ({ children }) => (
                        <div className="overflow-x-auto my-3 rounded-lg border border-gray-700/50">
                            <table className="w-full text-sm">{children}</table>
                        </div>
                    ),
                    thead: ({ children }) => (
                        <thead className="bg-gray-800/60 border-b border-gray-700/50">{children}</thead>
                    ),
                    tbody: ({ children }) => (
                        <tbody className="divide-y divide-gray-800/50">{children}</tbody>
                    ),
                    tr: ({ children }) => (
                        <tr className="hover:bg-white/[0.02] transition-colors">{children}</tr>
                    ),
                    th: ({ children }) => (
                        <th className="px-4 py-2.5 text-left text-xs font-bold text-gray-300 uppercase tracking-wider">
                            {children}
                        </th>
                    ),
                    td: ({ children }) => (
                        <td className="px-4 py-2.5 text-gray-300">{children}</td>
                    ),

                    // ═══ IMAGES ═══
                    img: ({ src, alt }) => (
                        <img src={src} alt={alt} className="rounded-lg max-w-full my-3 border border-gray-700/30 shadow-md" />
                    ),
                }}
            >
                {content}
            </ReactMarkdown>
        </div>
    );
};

export default MarkdownRenderer;
