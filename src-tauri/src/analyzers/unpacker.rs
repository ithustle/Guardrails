use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub struct UnpackedApk {
    pub extract_dir: PathBuf,
    pub manifest_data: Option<Vec<u8>>,
    pub dex_files: Vec<PathBuf>,
    pub asset_files: Vec<PathBuf>,
    pub resource_files: Vec<PathBuf>,
}

pub fn unpack_apk(apk_path: &Path, work_dir: &Path) -> Result<UnpackedApk, String> {
    let file = fs::File::open(apk_path)
        .map_err(|e| format!("Failed to open APK: {}", e))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| format!("Failed to read APK as ZIP: {}", e))?;

    let extract_dir = work_dir.join("unpacked");
    fs::create_dir_all(&extract_dir)
        .map_err(|e| format!("Failed to create extract dir: {}", e))?;

    let mut manifest_data: Option<Vec<u8>> = None;
    let mut dex_files: Vec<PathBuf> = Vec::new();
    let mut asset_files: Vec<PathBuf> = Vec::new();
    let mut resource_files: Vec<PathBuf> = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)
            .map_err(|e| format!("Failed to read ZIP entry: {}", e))?;

        let entry_name = match entry.enclosed_name() {
            Some(name) => name.to_path_buf(),
            None => continue,
        };

        let entry_name_str = entry_name.to_string_lossy().to_string();

        if entry_name_str == "AndroidManifest.xml" {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)
                .map_err(|e| format!("Failed to read AndroidManifest.xml: {}", e))?;
            manifest_data = Some(buf);
        } else if entry_name_str.ends_with(".dex") {
            let out_path = extract_dir.join(&entry_name);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).ok();
            }
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)
                .map_err(|e| format!("Failed to read DEX file: {}", e))?;
            fs::write(&out_path, &buf)
                .map_err(|e| format!("Failed to write DEX file: {}", e))?;
            dex_files.push(out_path);
        } else if entry_name_str.starts_with("assets/") {
            let out_path = extract_dir.join(&entry_name);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).ok();
            }
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).ok();
            fs::write(&out_path, &buf).ok();
            asset_files.push(out_path);
        } else if entry_name_str.starts_with("res/") {
            let out_path = extract_dir.join(&entry_name);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).ok();
            }
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).ok();
            fs::write(&out_path, &buf).ok();
            resource_files.push(out_path);
        }
    }

    Ok(UnpackedApk {
        extract_dir,
        manifest_data,
        dex_files,
        asset_files,
        resource_files,
    })
}
