import React, { useState, useRef, useEffect } from 'react';
import { Send, User, Bot, Loader2, Sparkles } from 'lucide-react';
import { aiService } from '../../services/aiService';
import MarkdownRenderer from '../common/MarkdownRenderer';

const AIChatBot = () => {
    const [messages, setMessages] = useState([
        { role: 'assistant', text: "Hello! I'm your **AI Security Analyst** powered by Groq. I can help you:\n\n- 🔍 Analyze scan results and threat reports\n- 🛡️ Explain malware behavior and attack techniques\n- 💡 Recommend remediation steps\n- 📊 Interpret network analysis findings\n\nHow can I assist you today?" }
    ]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [suggestions, setSuggestions] = useState([
        "What is ransomware?",
        "How do I recover from WannaCry?",
        "Explain the last scan result."
    ]);
    const messagesEndRef = useRef(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    const handleSend = async (text) => {
        if (!text.trim()) return;

        const userMsg = { role: 'user', text };
        setMessages(prev => [...prev, userMsg]);
        setInput('');
        setIsLoading(true);

        try {
            const data = await aiService.sendMessage(text);
            setMessages(prev => [...prev, { role: 'assistant', text: data.reply }]);
            if (data.suggestions) {
                setSuggestions(data.suggestions);
            }
        } catch (error) {
            setMessages(prev => [...prev, { role: 'assistant', text: '⚠️ Sorry, I am having trouble connecting to the intelligence database right now. Please try again in a moment.' }]);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="flex-1 flex flex-col h-full">
            {/* Chat History */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
                {messages.map((msg, idx) => (
                    <div key={idx} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                        {msg.role === 'assistant' && (
                            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500/20 to-cyan-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0 mt-0.5 shadow-lg shadow-indigo-500/10">
                                <Sparkles className="text-indigo-400" size={18} />
                            </div>
                        )}

                        <div className={`max-w-[85%] rounded-2xl ${msg.role === 'user'
                            ? 'bg-gradient-to-r from-indigo-600 to-blue-600 text-white px-5 py-3 rounded-br-md shadow-lg shadow-indigo-500/20'
                            : 'bg-dark-900/80 border border-gray-700/50 px-5 py-4 rounded-bl-md shadow-lg'
                            }`}>
                            {msg.role === 'user' ? (
                                <p className="text-white leading-relaxed">{msg.text}</p>
                            ) : (
                                <MarkdownRenderer content={msg.text} />
                            )}
                        </div>

                        {msg.role === 'user' && (
                            <div className="w-9 h-9 rounded-xl bg-gray-700/80 flex items-center justify-center shrink-0 mt-0.5 border border-gray-600/50">
                                <User className="text-gray-300" size={16} />
                            </div>
                        )}
                    </div>
                ))}

                {/* Typing indicator */}
                {isLoading && (
                    <div className="flex gap-3">
                        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500/20 to-cyan-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0 mt-0.5 shadow-lg shadow-indigo-500/10">
                            <Sparkles className="text-indigo-400" size={18} />
                        </div>
                        <div className="bg-dark-900/80 border border-gray-700/50 rounded-2xl rounded-bl-md px-5 py-4 shadow-lg">
                            <div className="flex items-center gap-3">
                                <div className="flex gap-1">
                                    <span className="w-2 h-2 rounded-full bg-indigo-400 animate-bounce" style={{ animationDelay: '0ms' }}></span>
                                    <span className="w-2 h-2 rounded-full bg-indigo-400 animate-bounce" style={{ animationDelay: '150ms' }}></span>
                                    <span className="w-2 h-2 rounded-full bg-indigo-400 animate-bounce" style={{ animationDelay: '300ms' }}></span>
                                </div>
                                <span className="text-sm text-gray-400">Analyzing threat intelligence...</span>
                            </div>
                        </div>
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>

            {/* Suggestion Chips */}
            {suggestions.length > 0 && !isLoading && (
                <div className="px-6 pb-3 flex flex-wrap gap-2">
                    {suggestions.map((suggestion, idx) => (
                        <button
                            key={idx}
                            onClick={() => handleSend(suggestion)}
                            className="px-4 py-2 bg-dark-800/80 hover:bg-indigo-500/10 border border-gray-600/50 hover:border-indigo-500/30 rounded-full text-sm text-gray-300 hover:text-indigo-300 transition-all duration-200"
                        >
                            {suggestion}
                        </button>
                    ))}
                </div>
            )}

            {/* Input Field */}
            <div className="p-4 border-t border-gray-700/50 bg-dark-800/80 rounded-b-xl backdrop-blur-sm">
                <form
                    className="flex gap-3"
                    onSubmit={(e) => { e.preventDefault(); handleSend(input); }}
                >
                    <input
                        type="text"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        disabled={isLoading}
                        placeholder="Ask about threats, file analyses, or remediation steps..."
                        className="flex-1 bg-dark-900/80 border border-gray-600/50 rounded-xl px-5 py-3.5 text-white placeholder-gray-500 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/20 disabled:opacity-50 transition-all"
                    />
                    <button
                        type="submit"
                        disabled={isLoading || !input.trim()}
                        className="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white px-6 py-3.5 rounded-xl font-medium transition-all disabled:from-gray-700 disabled:to-gray-700 disabled:cursor-not-allowed flex items-center gap-2 shadow-lg shadow-indigo-500/20 disabled:shadow-none"
                    >
                        <Send size={18} />
                        <span className="hidden sm:inline">Send</span>
                    </button>
                </form>
            </div>
        </div>
    );
};

export default AIChatBot;
