import { Component, type ReactNode } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import AnalyzePage from "./pages/AnalyzePage";
import ReportPage from "./pages/ReportPage";
import HistoryPage from "./pages/HistoryPage";
import SettingsPage from "./pages/SettingsPage";

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<
  { children: ReactNode },
  ErrorBoundaryState
> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            padding: "2rem",
            textAlign: "center",
            color: "#e5534b",
            fontFamily: "monospace",
          }}
        >
          <h1>Something went wrong</h1>
          <p>{this.state.error?.message || "An unexpected error occurred."}</p>
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null });
              window.location.hash = "/";
              window.location.reload();
            }}
            style={{
              marginTop: "1rem",
              padding: "0.5rem 1rem",
              background: "#4493f8",
              color: "#fff",
              border: "none",
              borderRadius: "6px",
              cursor: "pointer",
            }}
          >
            Reload Application
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<AnalyzePage />} />
            <Route path="/report/:id" element={<ReportPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  );
}

export default App;
