import React, { useState, useEffect, useRef } from 'react';

// Quick question suggestion chips
const SUGGESTIONS = [
  "You are a cybersecurity auditor. Use tools to find security risks.",
  "Write iptables rules to block database port 3306 for external IPs",
  "How do I secure an exposed SSH port 22?",
  "What is the difference between Quick and Full scans?"
];

export default function AiChatbot() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: '👋 Hello! I am your **AI Security Copilot**. You can talk to me in plain English to analyze security alerts, draft firewall configurations, or explain network scanning strategies. Try clicking one of the suggestions below!'
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef(null);

  // Scroll to bottom when messages list updates
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  const handleSend = async (textToSend) => {
    const text = textToSend || input;
    const trimmedText = text.trim();
    if (!trimmedText || isLoading) return;

    // Clear input
    if (!textToSend) setInput('');

    // 1. Add user message to state
    const userMsg = { role: 'user', content: trimmedText };
    setMessages((prev) => [...prev, userMsg]);
    setIsLoading(true);

    try {
      // 2. Format history for API (skip the welcome system message, map to simple schema)
      const historyPayload = messages
        .slice(1) // omit welcome message
        .map((m) => ({
          role: m.role,
          content: m.content
        }));

      // 3. Query the FastAPI chatbot endpoint
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: trimmedText,
          history: historyPayload
        })
      });

      if (!response.ok) {
        throw new Error('Copilot went offline. Please check your Ollama or server logs.');
      }

      const data = await response.json();

      // 4. Add assistant response
      setMessages((prev) => [...prev, { role: 'assistant', content: data.response }]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `❌ **Error**: ${err.message || 'Unable to connect to the Copilot.'}`
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  // Simple parser to render basic markdown elements: bold (**), backticks (`), lists (*), and headers (###)
  const renderFormattedText = (rawText) => {
    if (!rawText) return null;

    const lines = rawText.split('\n');
    return lines.map((line, lineIndex) => {
      let trimmed = line.trim();

      // Code blocks (triple backticks)
      if (trimmed.startsWith('```')) {
        return null; // Skip code block tags
      }

      // Headers (e.g., ### Title)
      if (trimmed.startsWith('###')) {
        return (
          <h4 key={lineIndex} className="text-sm font-bold text-gray-900 mt-3 mb-1">
            {trimmed.replace(/^###\s*/, '')}
          </h4>
        );
      }
      if (trimmed.startsWith('##')) {
        return (
          <h3 key={lineIndex} className="text-base font-bold text-gray-900 mt-4 mb-2">
            {trimmed.replace(/^##\s*/, '')}
          </h3>
        );
      }

      // Lists (e.g., * Item or 1. Item)
      if (trimmed.startsWith('*') || trimmed.startsWith('-')) {
        return (
          <ul key={lineIndex} className="list-disc pl-5 my-1 text-xs text-gray-700">
            <li>{parseInlineFormatting(trimmed.replace(/^[\*\-]\s*/, ''))}</li>
          </ul>
        );
      }
      if (/^\d+\.\s+/.test(trimmed)) {
        return (
          <ol key={lineIndex} className="list-decimal pl-5 my-1 text-xs text-gray-700">
            <li>{parseInlineFormatting(trimmed.replace(/^\d+\.\s+/, ''))}</li>
          </ol>
        );
      }

      // Default paragraph
      return (
        <p key={lineIndex} className="text-xs text-gray-700 leading-relaxed min-h-[1em] mb-1">
          {parseInlineFormatting(line)}
        </p>
      );
    });
  };

  // Parses bold (**) and inline code (`) formatting
  const parseInlineFormatting = (text) => {
    if (!text) return '';
    
    // Split by double asterisks first for bolding
    const boldParts = text.split('**');
    return boldParts.map((boldPart, bIdx) => {
      const isBold = bIdx % 2 !== 0;
      
      // For each bold/non-bold part, split by backticks for inline code styling
      const codeParts = boldPart.split('`');
      const renderedCodeParts = codeParts.map((codePart, cIdx) => {
        const isCode = cIdx % 2 !== 0;
        if (isCode) {
          return (
            <code key={cIdx} className="bg-gray-100 text-red-600 px-1 py-0.5 rounded font-mono text-xs">
              {codePart}
            </code>
          );
        }
        return codePart;
      });

      if (isBold) {
        return <strong key={bIdx} className="font-semibold text-gray-900">{renderedCodeParts}</strong>;
      }
      return <React.Fragment key={bIdx}>{renderedCodeParts}</React.Fragment>;
    });
  };

  return (
    <div className="bg-white shadow rounded-lg overflow-hidden flex flex-col h-[600px] border border-gray-200">
      {/* ── Chat Header ── */}
      <div className="bg-gradient-to-r from-violet-600 to-indigo-600 px-6 py-4 flex-shrink-0">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          💬 AI Security Copilot
        </h2>
        <p className="text-xs text-indigo-100 mt-0.5">
          Ask questions, analyze targets, or issue system commands to the cybersecurity auditor.
        </p>
      </div>

      {/* ── Chat Messages Pane ── */}
      <div className="flex-grow p-6 overflow-y-auto space-y-4 bg-slate-50">
        {messages.map((msg, index) => (
          <div
            key={index}
            className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-[75%] rounded-2xl px-4 py-3 shadow-sm border ${
                msg.role === 'user'
                  ? 'bg-indigo-600 text-white border-indigo-700 rounded-br-none'
                  : 'bg-white text-gray-800 border-gray-200 rounded-bl-none'
              }`}
            >
              {/* Message Header Avatar/Icon */}
              <div className="text-[10px] font-bold uppercase tracking-wider mb-1 flex items-center gap-1.5 opacity-70">
                {msg.role === 'user' ? (
                  <>🧑 Operator</>
                ) : (
                  <>🤖 Auditor Copilot</>
                )}
              </div>
              <div className={msg.role === 'user' ? 'text-xs text-white leading-relaxed' : ''}>
                {msg.role === 'user' ? msg.content : renderFormattedText(msg.content)}
              </div>
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex justify-start">
            <div className="bg-white text-gray-800 border border-gray-200 rounded-2xl rounded-bl-none px-4 py-3 shadow-sm max-w-[75%]">
              <div className="text-[10px] font-bold uppercase tracking-wider mb-1 flex items-center gap-1.5 opacity-70">
                🤖 Auditor Copilot
              </div>
              <div className="flex items-center gap-1.5 py-1.5 px-1">
                <div className="w-1.5 h-1.5 bg-gray-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <div className="w-1.5 h-1.5 bg-gray-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <div className="w-1.5 h-1.5 bg-gray-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* ── Suggestion Chips ── */}
      <div className="px-6 py-2.5 bg-gray-50 border-t border-gray-100 flex-shrink-0">
        <div className="text-[10px] font-semibold text-gray-500 mb-1.5 uppercase tracking-wide">
          Suggested Prompts:
        </div>
        <div className="flex flex-wrap gap-2">
          {SUGGESTIONS.map((sug, i) => (
            <button
              key={i}
              className="text-[11px] bg-white hover:bg-indigo-50 text-indigo-700 hover:text-indigo-800 border border-gray-200 hover:border-indigo-300 font-medium px-2.5 py-1.5 rounded-full shadow-sm transition duration-150 ease-in-out text-left max-w-full truncate"
              onClick={() => handleSend(sug)}
              disabled={isLoading}
            >
              {sug}
            </button>
          ))}
        </div>
      </div>

      {/* ── Input Panel ── */}
      <div className="p-4 bg-white border-t border-gray-200 flex-shrink-0">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex gap-2"
        >
          <input
            type="text"
            className="flex-grow text-xs border border-gray-300 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 shadow-inner"
            placeholder="Type a message or cybersecurity instruction..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={isLoading}
          />
          <button
            type="submit"
            className="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs px-6 py-3 rounded-lg shadow-sm transition duration-150 ease-in-out flex items-center gap-1"
            disabled={isLoading || !input.trim()}
          >
            Send ➔
          </button>
        </form>
      </div>
    </div>
  );
}
