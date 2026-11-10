//! File metadata presentation. Byte credentials and file contents stay outside it.
use super::visible;
use ssh_core::files::{FileInfo, FileKind, Metadata};

#[derive(serde::Serialize)]
pub struct FileShown {
    pub fields: Vec<(String, String)>,
    pub entries: Vec<DirectoryShown>,
    pub notice: String,
    pub artifact: String,
    pub modified: Option<u32>,
}

#[derive(serde::Serialize)]
pub struct DirectoryShown {
    pub name: String,
    pub kind: String,
    pub bytes: String,
    pub permissions: String,
    pub modified: Option<u32>,
}

fn kind_name(kind: FileKind) -> &'static str {
    match kind {
        FileKind::File => "File",
        FileKind::Directory => "Directory",
        FileKind::Other => "Other",
    }
}

fn permissions(value: Option<u32>) -> String {
    value
        .map(|value| format!("{value:04o}"))
        .unwrap_or_else(|| "Unavailable".to_owned())
}

fn metadata_fields(fields: &mut Vec<(String, String)>, value: &Metadata) {
    fields.push(("Type".to_owned(), kind_name(value.kind).to_owned()));
    fields.push((
        "Size".to_owned(),
        value
            .bytes
            .map(|bytes| format!("{bytes} bytes"))
            .unwrap_or_else(|| "Unavailable".to_owned()),
    ));
    fields.push((
        "Permissions (octal)".to_owned(),
        permissions(value.permissions),
    ));
}

pub(super) fn retained_operation(info: Option<&FileInfo>, artifact: bool) -> &'static str {
    match info {
        Some(FileInfo::Stat { .. }) => "stat",
        Some(FileInfo::List { .. }) => "list",
        Some(FileInfo::Checksum { .. }) => "checksum",
        None if artifact => "files",
        None => "unknown",
    }
}

pub(super) fn describe(
    kind: &str,
    arguments: &[String],
    event: Option<&serde_json::Value>,
) -> Option<FileShown> {
    if kind == "execute"
        || (kind == "unknown"
            && event.is_none_or(|event| {
                event.get("file").is_none_or(serde_json::Value::is_null)
                    && event.get("info").is_none_or(serde_json::Value::is_null)
            }))
    {
        return None;
    }
    let program = match kind {
        "upload" => "file.upload",
        "download" => "file.download",
        "stat" => "file.stat",
        "list" => "file.list",
        "checksum" => "file.checksum",
        "unknown" | "files" => "",
        _ => return None,
    };
    let mut shown = FileShown {
        fields: Vec::new(),
        entries: Vec::new(),
        notice: String::new(),
        artifact: String::new(),
        modified: None,
    };
    let known = arguments
        .first()
        .is_some_and(|argument| argument == program);
    if known {
        shown.fields.push((
            if kind == "upload" {
                "Remote destination"
            } else {
                "Remote source path"
            }
            .to_owned(),
            arguments
                .get(1)
                .map(|path| visible(path))
                .unwrap_or_else(|| "Unavailable".to_owned()),
        ));
        if kind == "upload" {
            for (index, label) in [
                (2, "Source bytes"),
                (3, "Source SHA-256"),
                (4, "Write mode"),
            ] {
                shown.fields.push((
                    label.to_owned(),
                    arguments
                        .get(index)
                        .map(|value| visible(value))
                        .unwrap_or_else(|| "Unavailable".to_owned()),
                ));
            }
            if arguments.get(5).is_some_and(|value| value == "staged") {
                shown.fields.push((
                    "Remote staging path".to_owned(),
                    arguments
                        .get(6)
                        .map(|path| visible(path))
                        .unwrap_or_else(|| "Unavailable".to_owned()),
                ));
                shown.notice = "Staging and final destination are distinct. Inspect any replacement or cleanup failure before requesting further work.".to_owned();
            }
        }
    } else {
        shown.notice = "Structured path fields are unavailable for this older representation. Inspect the exact operation arguments.".to_owned();
    }
    if let Some(event) = event {
        if let Some(file) = event.get("file").filter(|value| !value.is_null()) {
            for (field, label) in [("bytes", "Result bytes"), ("sha256", "Result SHA-256")] {
                if let Some(value) = file.get(field) {
                    shown.fields.push((
                        label.to_owned(),
                        visible(
                            &value
                                .as_str()
                                .map_or_else(|| value.to_string(), str::to_owned),
                        ),
                    ));
                }
            }
        }
        if let Some(info) = event.get("info").filter(|value| !value.is_null()) {
            match serde_json::from_value::<FileInfo>(info.clone()).ok().filter(FileInfo::is_bounded) {
                Some(FileInfo::Stat { metadata }) => { metadata_fields(&mut shown.fields, &metadata); shown.modified = metadata.modified; }
                Some(FileInfo::Checksum { bytes, sha256 }) => {
                    shown.fields.extend([("Algorithm".to_owned(), "SHA-256".to_owned()), ("Bytes observed".to_owned(), bytes.to_string()), ("Observed digest".to_owned(), sha256)]);
                    shown.notice = "Checksum describes the observed content; the remote file may change afterward.".to_owned();
                }
                Some(FileInfo::List { entries, truncated }) => {
                    let withheld = entries.iter().filter(|entry| entry.name.is_none()).count();
                    shown.notice = format!("{} entries retained · {withheld} names withheld{}", entries.len(), if truncated { " · listing incomplete; request a narrower listing to investigate further" } else { " · listing completed within the service limit" });
                    shown.entries = entries.into_iter().map(|entry| DirectoryShown {
                        name:entry.name.as_deref().map(visible).unwrap_or_else(|| "Name withheld".to_owned()), kind:kind_name(entry.metadata.kind).to_owned(), bytes:entry.metadata.bytes.map(|value| value.to_string()).unwrap_or_else(|| "Unavailable".to_owned()), permissions:permissions(entry.metadata.permissions), modified:entry.metadata.modified,
                    }).collect();
                }
                None => shown.notice = "Metadata result is unavailable or unsupported. Retained operation evidence is still shown.".to_owned(),
            }
        }
    }
    if kind == "download" {
        shown.artifact = "Artifact availability is not established for this operator. A retained file reference does not grant a browser download; use the authorized agent byte channel.".to_owned();
    } else if kind == "upload" {
        shown.artifact = "Result metadata identifies the upload. It does not make the original upload reference downloadable.".to_owned();
    }
    Some(shown)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn presenters_follow_the_explicit_operation_kind() {
        assert!(describe("execute", &["file.upload".to_owned()], None).is_none());
        for kind in ["upload", "download", "stat", "list", "checksum"] {
            let arguments = vec![
                format!("file.{kind}"),
                "/srv/full path".to_owned(),
                "12".to_owned(),
                "a".repeat(64),
                "replace".to_owned(),
                "staged".to_owned(),
                "/srv/staging".to_owned(),
            ];
            let shown = describe(kind, &arguments, None).unwrap();
            assert!(
                shown
                    .fields
                    .iter()
                    .any(|(_, value)| value == "/srv/full path")
            );
            if kind == "upload" {
                assert!(
                    shown
                        .fields
                        .iter()
                        .any(|(_, value)| value == "/srv/staging")
                );
            }
        }
    }

    #[test]
    fn incomplete_directory_results_keep_withheld_names_explicit() {
        let event = serde_json::json!({"info":{"operation":"list","entries":[{"name":null,"metadata":{"kind":"file","bytes":12,"permissions":384,"modified":0}}],"truncated":true}});
        let shown = describe(
            "list",
            &["file.list".to_owned(), "/srv".to_owned()],
            Some(&event),
        )
        .unwrap();
        assert!(shown.notice.contains("1 names withheld"));
        assert!(shown.notice.contains("listing incomplete"));
        assert_eq!(shown.entries.first().unwrap().name, "Name withheld");
        assert_eq!(shown.entries.first().unwrap().permissions, "0600");
    }
}
