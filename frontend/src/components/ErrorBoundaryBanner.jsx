import React from 'react';

export default function ErrorBoundaryBanner({ visible }) {
  if (!visible) return null;
  return (
    <div id="error-boundary-banner" className="bg-red-600 text-white text-center py-2 px-4 font-semibold w-full">
      Warning: Connection lost or server error (500). Please try again later.
    </div>
  );
}
