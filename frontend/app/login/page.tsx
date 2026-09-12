"use client";

import { useState } from "react";
import { supabase } from "../../lib/supabase";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");

  const handleLogin = async () => {
    setMessage("Sending magic link...");
    const { error } = await supabase.auth.signInWithOtp({ email });
    if (error) {
      setMessage(`Login error: ${error.message}`);
      return;
    }
    setMessage("Magic link sent. Check your email.");
  };

  return (
    <main className="container">
      <h1>Login</h1>
      <div className="card">
        <p>Sign in with Supabase magic link.</p>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@example.com"
        />
        <div style={{ marginTop: 12 }}>
          <button onClick={handleLogin}>Send Magic Link</button>
        </div>
        <p>{message}</p>
      </div>
    </main>
  );
}
