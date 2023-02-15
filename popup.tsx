import React from 'react';
import ReactDOM from 'react-dom';
import Popup from './lib/Popup';

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  const { url } = tab;
  ReactDOM.render(
    <React.StrictMode>
      <Popup url={url ? new URL(url).hostname : undefined} />
    </React.StrictMode>,
    document.getElementById('root')
  );
});
