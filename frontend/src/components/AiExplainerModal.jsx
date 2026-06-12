import React, { useState, useEffect } from 'react';

export default function AiExplainerModal({ visible, sourceType, sourceId, onClose }) {
  const [explanation, setExplanation] = useState('Thinking...');
  const [severity, setSeverity] = useState('Loading...');
  const [remediation, setRemediation] = useState('');
  const [infoText, setInfoText] = useState('');

  useEffect(() => {
    if (!visible || !sourceId) return;

    setExplanation('Thinking...');
    setSeverity('Loading...');
    setRemediation('Retrieving threat remediation protocol...');
    setInfoText(`Generating AI explanation for ${sourceType.toUpperCase()} ID #${sourceId}...`);

    const fetchExplanation = async () => {
      try {
        const response = await fetch('/api/explain', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ source_type: sourceType, source_id: sourceId })
        });

        if (!response.ok) throw new Error("Fallback failed");

        const data = await response.json();
        setExplanation(data.explanation);
        setSeverity(data.severity);
        setRemediation(data.remediation);
        setInfoText(`Source Context: ${sourceType.toUpperCase()} Record #${sourceId}`);
      } catch (err) {
        setInfoText("Error retrieving explanation.");
        setExplanation("The AI Threat Explainer module could not respond. Standard fallback error returned.");
        setSeverity("UNKNOWN");
        setRemediation("Inspect network connectivity or verify local Ollama mock-fallback is enabled.");
      }
    };

    fetchExplanation();
  }, [visible, sourceType, sourceId]);

  if (!visible) return null;

  const getSeverityBadgeClass = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'bg-red-200 text-red-900 border border-red-300';
      case 'high': return 'bg-orange-200 text-orange-900 border border-orange-300';
      case 'medium': return 'bg-amber-200 text-amber-900 border border-amber-300';
      case 'low': return 'bg-blue-100 text-blue-800 border border-blue-200';
      default: return 'bg-gray-200 text-gray-800 border border-gray-300';
    }
  };

  return (
    <div id="ai-explainer-modal" className="fixed inset-0 bg-slate-900 bg-opacity-70 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full flex flex-col max-h-[90vh]">
        
        {/* Modal Header */}
        <div className="bg-slate-900 text-white px-6 py-4 flex justify-between items-center rounded-t-lg">
          <h3 className="text-lg font-bold">Threat Explanation & Remediation</h3>
          <button className="text-slate-400 hover:text-white text-xl font-bold" onClick={onClose}>&times;</button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-4">
          <div>
            <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Threat Context</span>
            <p id="ai-source-info" className="text-sm font-semibold text-slate-800 mt-1">{infoText}</p>
          </div>
          <hr className="border-gray-200" />
          
          <div>
            <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">AI Security Assessment</span>
            <div className="mt-2 bg-blue-50 border border-blue-200 text-blue-900 rounded p-4 text-sm whitespace-pre-line" id="ai-explanation">
              {explanation}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Severity Level</span>
              <div className="mt-1">
                <span id="ai-severity" className={`px-2.5 py-1 text-xs font-bold rounded uppercase ${getSeverityBadgeClass(severity)}`}>
                  {severity}
                </span>
              </div>
            </div>
            <div>
              <span className="text-xs font-bold text-gray-400 uppercase tracking-wider font-semibold">Remediation Steps</span>
              <div className="mt-1 text-sm text-gray-700 bg-emerald-50 border border-emerald-100 rounded p-3" id="ai-remediation">
                {remediation}
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="bg-gray-50 px-6 py-4 flex justify-end rounded-b-lg border-t border-gray-200">
          <button id="btn-close-explainer" className="bg-slate-800 hover:bg-slate-700 text-white font-medium py-2 px-4 rounded" onClick={onClose}>
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}
