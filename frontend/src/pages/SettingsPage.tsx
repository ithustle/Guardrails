import { useState, useEffect, useCallback } from "react";
import { Save, Loader2 } from "lucide-react";
import { getSettings, saveSettings } from "../lib/api";
import type { AppSettings } from "../lib/types";

export default function SettingsPage() {
  const [settings, setSettings] = useState<AppSettings>({
    virustotal_api_key: null,
    rules_path: null,
  });
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    getSettings()
      .then(setSettings)
      .catch((e) => setLoadError(`Failed to load settings: ${e}`))
      .finally(() => setLoading(false));
  }, []);

  const handleSave = useCallback(async () => {
    setSaving(true);
    setMessage(null);
    try {
      await saveSettings(settings);
      setMessage("Settings saved successfully.");
      setTimeout(() => setMessage(null), 5000);
    } catch (e) {
      setMessage(`Failed to save settings: ${e}`);
    } finally {
      setSaving(false);
    }
  }, [settings]);

  if (loading) {
    return (
      <div className="page loading-page">
        <Loader2 size={32} className="spinner" />
        <p>Loading settings...</p>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="page">
        <div className="error-message">{loadError}</div>
      </div>
    );
  }

  return (
    <div className="page settings-page">
      <h1>Settings</h1>

      <div className="settings-form">
        <div className="form-group">
          <label htmlFor="vt-key">VirusTotal API Key</label>
          <input
            id="vt-key"
            type="password"
            placeholder="Enter your VirusTotal API key"
            value={settings.virustotal_api_key || ""}
            onChange={(e) =>
              setSettings({
                ...settings,
                virustotal_api_key: e.target.value || null,
              })
            }
          />
          <p className="form-hint">
            Get your free API key from{" "}
            <a
              href="https://www.virustotal.com"
              target="_blank"
              rel="noopener noreferrer"
            >
              virustotal.com
            </a>
          </p>
        </div>

        <div className="form-group">
          <label htmlFor="rules-path">Rules File Path</label>
          <input
            id="rules-path"
            type="text"
            placeholder="Default: app data directory"
            value={settings.rules_path || ""}
            onChange={(e) =>
              setSettings({
                ...settings,
                rules_path: e.target.value || null,
              })
            }
          />
          <p className="form-hint">
            Path to custom rules.toml file. Leave empty to use default.
          </p>
        </div>

        {message && (
          <div
            className={
              message.includes("Failed") ? "error-message" : "success-message"
            }
          >
            {message}
          </div>
        )}

        <button
          className="btn btn-primary"
          onClick={handleSave}
          disabled={saving}
        >
          {saving ? (
            <Loader2 size={16} className="spinner" />
          ) : (
            <Save size={16} />
          )}
          Save Settings
        </button>
      </div>
    </div>
  );
}
