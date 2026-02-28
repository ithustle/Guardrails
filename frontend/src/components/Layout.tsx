import { NavLink, Outlet } from "react-router-dom";
import { Upload, History, Settings, Shield } from "lucide-react";

export default function Layout() {
  return (
    <div className="app-layout">
      <nav className="sidebar">
        <div className="sidebar-header">
          <Shield size={28} />
          <span className="sidebar-title">Guardrails</span>
        </div>
        <div className="sidebar-nav">
          <NavLink to="/" end className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
            <Upload size={18} />
            <span>Analyze</span>
          </NavLink>
          <NavLink to="/history" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
            <History size={18} />
            <span>History</span>
          </NavLink>
          <NavLink to="/settings" className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}>
            <Settings size={18} />
            <span>Settings</span>
          </NavLink>
        </div>
      </nav>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
