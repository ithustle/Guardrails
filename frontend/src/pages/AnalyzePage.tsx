import { useState, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { Upload, FileSearch, Loader2 } from "lucide-react";
import { analyzeApk } from "../lib/api";

export default function AnalyzePage() {
  const [apkPath, setApkPath] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const navigate = useNavigate();

  // Listen for Tauri native file drop events (provides full paths)
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    getCurrentWebview()
      .onDragDropEvent((event) => {
        if (event.payload.type === "enter" || event.payload.type === "over") {
          setDragOver(true);
        } else if (event.payload.type === "leave") {
          setDragOver(false);
        } else if (event.payload.type === "drop") {
          setDragOver(false);
          const paths = event.payload.paths;
          if (paths.length > 0) {
            const droppedPath = paths[0];
            if (droppedPath.endsWith(".apk")) {
              setApkPath(droppedPath);
              setError(null);
            } else {
              setError("Please drop an APK file (.apk)");
            }
          }
        }
      })
      .then((fn) => {
        unlisten = fn;
      });

    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const selectFile = useCallback(async () => {
    try {
      const selected = await open({
        multiple: false,
        filters: [{ name: "APK Files", extensions: ["apk"] }],
      });
      if (selected) {
        setApkPath(selected as string);
        setError(null);
      }
    } catch (e) {
      setError(`Failed to open file dialog: ${e}`);
    }
  }, []);

  const handleAnalyze = useCallback(async () => {
    if (!apkPath) return;
    setAnalyzing(true);
    setError(null);
    try {
      const report = await analyzeApk(apkPath);
      navigate(`/report/${report.id}`);
    } catch (e) {
      setError(`Analysis failed: ${e}`);
    } finally {
      setAnalyzing(false);
    }
  }, [apkPath, navigate]);

  return (
    <div className="page analyze-page">
      <h1>Analyze APK</h1>
      <p className="page-subtitle">
        Select an Android APK file to analyze for Google Play policy compliance.
      </p>

      <div
        className={`drop-zone ${dragOver ? "drag-over" : ""} ${apkPath ? "has-file" : ""}`}
        onClick={selectFile}
      >
        {apkPath ? (
          <>
            <FileSearch size={48} strokeWidth={1.5} />
            <p className="drop-zone-filename">{apkPath.split(/[/\\]/).pop()}</p>
            <p className="drop-zone-hint">Click to change file</p>
          </>
        ) : (
          <>
            <Upload size={48} strokeWidth={1.5} />
            <p>Click to select an APK file</p>
            <p className="drop-zone-hint">or drag and drop here</p>
          </>
        )}
      </div>

      {error && <div className="error-message">{error}</div>}

      <button
        className="btn btn-primary analyze-btn"
        onClick={handleAnalyze}
        disabled={!apkPath || analyzing}
      >
        {analyzing ? (
          <>
            <Loader2 size={18} className="spinner" />
            Analyzing...
          </>
        ) : (
          <>
            <FileSearch size={18} />
            Analyze
          </>
        )}
      </button>
    </div>
  );
}
