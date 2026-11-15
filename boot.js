// Load the online SDK only when a real Supabase backend has been configured.
// This keeps demo mode usable without Internet access.
(() => {
  const c = window.SITEARCHITECT_CONFIG || {};
  function loadApp() { const script=document.createElement('script');script.src='app.js';document.head.appendChild(script); }
  if (!c.supabaseUrl || !c.supabasePublishableKey) return loadApp();
  const sdk=document.createElement('script');
  sdk.src='https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2';
  sdk.onload=loadApp;
  sdk.onerror=loadApp;
  document.head.appendChild(sdk);
})();
