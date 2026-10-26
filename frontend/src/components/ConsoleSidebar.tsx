import { Activity, BarChart3, FileSearch, ShieldCheck } from "lucide-react";
import type { Health } from "../api";

export default function ConsoleSidebar({ health }: { health: Health | null }) {
  return (
    <aside className="console-sidebar">
      <div className="brand">
        <div className="brand-mark"><ShieldCheck size={19} /></div>
        <div className="brand-copy">
          <div className="brand-name">NetGuard AI</div>
          <div className="brand-subtitle">Traffic security console</div>
        </div>
      </div>

      <div className="nav-kicker">Workspace</div>
      <nav className="console-nav" aria-label="Dashboard sections">
        <a href="#analysis"><Activity size={17} /><span>Traffic analysis</span></a>
        <a href="#results"><FileSearch size={17} /><span>Prediction results</span></a>
        <a href="#evaluation"><BarChart3 size={17} /><span>Model evaluation</span></a>
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-footer-label">Detection engine</div>
        <div className="sidebar-footer-value">
          <span className="status-dot" />
          {health?.model_loaded ? health.model_name ?? "Model ready" : "Awaiting model"}
        </div>
      </div>
    </aside>
  );
}
