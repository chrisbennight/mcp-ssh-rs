//! Typed execution and file-transfer intent used by review and audit.

use crate::command::{Command, CommandError};
use crate::files::RemotePath;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Execute,
    Download,
    Upload,
    Stat,
    List,
    Checksum,
}

impl ActionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::Download => "download",
            Self::Upload => "upload",
            Self::Stat => "stat",
            Self::List => "list",
            Self::Checksum => "checksum",
        }
    }
}

/// File content identity, excluding the content itself.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct FileIdentity {
    pub uri: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Execute,
    Download {
        path: RemotePath,
    },
    FileInfo {
        path: RemotePath,
        operation: crate::files::InfoOperation,
    },
    Upload {
        path: RemotePath,
        source: FileIdentity,
        overwrite: bool,
        staging_path: Option<RemotePath>,
    },
}

/// The display arguments never determine which backend executes the action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    operation: Operation,
    command: Command,
}

impl Action {
    pub const fn execute(command: Command) -> Self {
        Self {
            operation: Operation::Execute,
            command,
        }
    }

    pub fn download(path: RemotePath) -> Result<Self, CommandError> {
        let command = Command::new(vec!["file.download".to_owned(), path.as_str().to_owned()])?;
        Ok(Self {
            operation: Operation::Download { path },
            command,
        })
    }

    pub fn file_info(
        path: RemotePath,
        operation: crate::files::InfoOperation,
    ) -> Result<Self, CommandError> {
        let program = match operation {
            crate::files::InfoOperation::Stat => "file.stat",
            crate::files::InfoOperation::List => "file.list",
            crate::files::InfoOperation::Checksum => "file.checksum",
        };
        let command = Command::new(vec![program.to_owned(), path.as_str().to_owned()])?;
        Ok(Self {
            operation: Operation::FileInfo { path, operation },
            command,
        })
    }

    pub fn upload(
        path: RemotePath,
        source: FileIdentity,
        overwrite: bool,
    ) -> Result<Self, CommandError> {
        Self::upload_with_staging(path, source, overwrite, None)
    }

    pub fn upload_with_staging(
        path: RemotePath,
        source: FileIdentity,
        overwrite: bool,
        staging_path: Option<RemotePath>,
    ) -> Result<Self, CommandError> {
        let mut argv = vec![
            "file.upload".to_owned(),
            path.as_str().to_owned(),
            source.bytes.to_string(),
            source.sha256.clone(),
            if overwrite { "replace" } else { "create_new" }.to_owned(),
        ];
        if let Some(stage) = &staging_path {
            argv.extend(["staged".to_owned(), stage.as_str().to_owned()]);
        }
        let command = Command::new(argv)?;
        Ok(Self {
            operation: Operation::Upload {
                path,
                source,
                overwrite,
                staging_path,
            },
            command,
        })
    }

    pub const fn kind(&self) -> ActionKind {
        match &self.operation {
            Operation::Execute => ActionKind::Execute,
            Operation::Download { .. } => ActionKind::Download,
            Operation::Upload { .. } => ActionKind::Upload,
            Operation::FileInfo { operation, .. } => match operation {
                crate::files::InfoOperation::Stat => ActionKind::Stat,
                crate::files::InfoOperation::List => ActionKind::List,
                crate::files::InfoOperation::Checksum => ActionKind::Checksum,
            },
        }
    }

    pub const fn operation(&self) -> &Operation {
        &self.operation
    }
    pub const fn command(&self) -> &Command {
        &self.command
    }
}
