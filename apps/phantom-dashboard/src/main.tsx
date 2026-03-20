import React from 'react';
import ReactDOM from 'react-dom/client';

import 'uplot/dist/uPlot.min.css';
import './styles.css';

import { App } from './App';

const rootEl = document.getElementById('app');
if (!rootEl) {
  throw new Error('app root element (#app) nicht gefunden');
}

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
