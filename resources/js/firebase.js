import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";

const firebaseConfig = {
  apiKey: process.env.MIX_API_KEY,
  authDomain: process.env.MIX_AUTH_DOMAIN,
  projectId: process.env.MIX_PROJECT_ID,
  storageBucket: process.env.MIX_STORAGE_BUCKET,
  messagingSenderId: process.env.MIX_MESSAGING_SENDER_ID,
  appId: process.env.MIX_APP_ID
};

const app = initializeApp(firebaseConfig);

export const provider = new GoogleAuthProvider();
export const auth = getAuth(app);

auth.languageCode = 'fr';
