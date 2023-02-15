import { IP_STATUS } from './lib/status';

const FILTER = {
  types: ['main_frame' as chrome.webRequest.ResourceType],
  urls: ['https://*/*']
};
const IPS: { [hostname: string]: string | null } = {};
const PENDING: { [hostname: string]: number } = {};

export interface Message {
  status: IP_STATUS
  ip?: string
}

chrome.webRequest.onBeforeRequest.addListener((details) => {
  const { url } = details;
  IPS[new URL(url).hostname] = null;
}, FILTER);

chrome.webRequest.onCompleted.addListener((details) => {
  const { ip, url } = details;
  const { hostname } = new URL(url);
  if (!ip) {
    throw new Error('Request completed but no ip');
  }

  IPS[hostname] = ip;

  // Send the ip to an active popup
  const tabId = PENDING[hostname];
  if (tabId) {
    chrome.tabs.sendMessage<Message, undefined>(tabId, { status: IP_STATUS.RESOLVED, ip });
  }
}, FILTER);

chrome.runtime.onMessage.addListener((hostname, sender, sendResponse) => {
  const ip = IPS[hostname];
  if (ip === null) {
    // Remember which tab asked for this hostname. There can only be one such
    // tab as only one popup can be open. Tab switches close the popup.
    const senderId = sender.tab?.id;
    if (senderId) {
      PENDING[hostname] = senderId;
    }
    sendResponse({ status: IP_STATUS.PENDING });
  } else if (ip) {
    sendResponse({ status: IP_STATUS.RESOLVED, ip });
  } else {
    sendResponse({ status: IP_STATUS.NO_REQUEST });
  }
});
