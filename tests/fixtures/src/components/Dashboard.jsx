// Fixture: Typical vibe-coded React component with client-side issues.
import { useState, useEffect } from 'react';

export default function Dashboard() {
  const [user, setUser] = useState(null);

  // ❌ Client-only auth guard
  useEffect(() => {
    if (!user) {
      window.location.href = '/login';
    }
  }, [user]);

  // ❌ Token in localStorage
  const login = async (email, password) => {
    const res = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
    const data = await res.json();
    localStorage.setItem("authToken", data.token);
    setUser(data.user);
  };

  // ❌ Client-side price calculation
  const totalPrice = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);

  // ❌ Admin check only on client
  return (
    <div>
      {isAdmin && (
        <button onClick={deleteAllUsers}>Delete All Users</button>
      )}
      <p>Total: ${totalPrice}</p>
      {/* ❌ Console logging sensitive data */}
    </div>
  );
}
