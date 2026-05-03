// useSession.js — IndexedDB session persistence
// Saves parsed results so user doesn't re-upload

const DB_NAME = 'sniffpal';
const DB_VERSION = 1;
const STORE = 'sessions';
const SESSION_KEY = 'last_session';
const EXPIRY_HOURS = 24;

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      e.target.result.createObjectStore(STORE);
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = () => reject(req.error);
  });
}

export async function saveSession(data, fileName) {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put({
      data,
      fileName,
      savedAt: Date.now(),
    }, SESSION_KEY);
    return true;
  } catch {
    return false;
  }
}

export async function loadSession() {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(SESSION_KEY);
    return new Promise((resolve) => {
      req.onsuccess = () => {
        const result = req.result;
        if (!result) return resolve(null);
        // Check expiry
        const hours = (Date.now() - result.savedAt) / 1000 / 60 / 60;
        if (hours > EXPIRY_HOURS) return resolve(null);
        resolve(result);
      };
      req.onerror = () => resolve(null);
    });
  } catch {
    return null;
  }
}

export async function clearSession() {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(SESSION_KEY);
    return true;
  } catch {
    return false;
  }
}

export function timeAgo(timestamp) {
  const mins = Math.floor((Date.now() - timestamp) / 1000 / 60);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} minute${mins > 1 ? 's' : ''} ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} hour${hrs > 1 ? 's' : ''} ago`;
  return 'yesterday';
}
