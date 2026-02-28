import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { open } from "@tauri-apps/plugin-dialog";
import { Upload, FileSearch, Loader2 } from "lucide-react";
import { analyzeApk } from "../lib/api";

export default function AnalyzePage() {
  const [apkPath, setApkPath] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const navigate = useNavigate();

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

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      if (file.name.endsWith(".apk")) {
        // In Tauri, we need the full path which we can get from the File object
        // For drag and drop in Tauri v2, we use the path property
        setApkPath(file.name);
        setError("Drag and drop may not provide full file path. Please use the file picker instead.");
      } else {
        setError("Please select an APK file (.apk)");
      }
    }
  }, []);

  return (
    <div className="page analyze-page">
      <h1>Analyze APK</h1>
      <p className="page-subtitle">
        Select an Android APK file to analyze for Google Play policy compliance.
      </p>

      <div
        className={`drop-zone ${dragOver ? "drag-over" : ""} ${apkPath ? "has-file" : ""}`}
        onClick={selectFile}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
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
