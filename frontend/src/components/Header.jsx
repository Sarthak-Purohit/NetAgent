import React from 'react';

export default function Header() {
  return (
    <header className="bg-slate-900 text-white shadow-md">
      <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
        <h1 className="text-xl font-bold tracking-tight">NetAgent Security Ops Center</h1>
        <span className="text-xs px-2 py-1 rounded bg-blue-600 font-semibold" id="env-badge">PRODUCTION</span>
      </div>
    </header>
  );
}
