//! Stdio file references resolve inside an operator-configured shared directory.

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use ssh_core::transfer::PreparedUpload;
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct LocalFiles {
    root: PathBuf,
    root_fd: File,
    output: Arc<OutputDirectory>,
    active: Arc<Semaphore>,
}

struct OutputDirectory {
    parent: File,
    fd: File,
    name: String,
    path: PathBuf,
}
pub struct OwnedFile {
    directory: Arc<OutputDirectory>,
    name: String,
}

impl LocalFiles {
    pub fn new(root: &Path) -> std::io::Result<Self> {
        let root = root.canonicalize()?;
        let root_fd = File::open(&root)?;
        if !root_fd.metadata()?.is_dir() {
            return Err(std::io::Error::other("shared file root is not a directory"));
        }
        let mut random = [0_u8; 16];
        rand::fill(&mut random);
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = format!(".mcp-ssh-{suffix}");
        mkdirat(&root_fd, name.as_str(), Mode::S_IRWXU)?;
        let fd = File::from(openat(
            &root_fd,
            name.as_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        let output = Arc::new(OutputDirectory {
            parent: root_fd.try_clone()?,
            fd,
            path: root.join(&name),
            name,
        });
        Ok(Self {
            root,
            root_fd,
            output,
            active: Arc::new(Semaphore::new(16)),
        })
    }

    pub fn uri(&self, name: &str) -> std::io::Result<String> {
        validate_name(name)?;
        url::Url::from_file_path(self.output.path.join(name))
            .map(String::from)
            .map_err(|()| std::io::Error::other("output path cannot be represented as a file URI"))
    }

    #[cfg(test)]
    pub async fn read(
        self: &Arc<Self>,
        uri: &str,
        staging: Arc<File>,
        limit: u64,
    ) -> std::io::Result<PreparedUpload> {
        self.read_pinned(uri, staging, limit, None).await
    }

    pub fn output_id(&self, uri: &str) -> Option<String> {
        let uri = url::Url::parse(uri).ok()?;
        if uri.query().is_some() || uri.fragment().is_some() {
            return None;
        }
        let path = uri.to_file_path().ok()?;
        let relative = path.strip_prefix(&self.output.path).ok()?;
        let name = relative.to_str()?;
        validate_name(name).ok()?;
        Some(name.to_owned())
    }

    pub async fn read_pinned(
        self: &Arc<Self>,
        uri: &str,
        staging: Arc<File>,
        limit: u64,
        source: Option<Arc<crate::disk::Snapshot>>,
    ) -> std::io::Result<PreparedUpload> {
        let permit = Arc::clone(&self.active)
            .try_acquire_owned()
            .map_err(|_| std::io::Error::other("local input capacity is exhausted"))?;
        let (mut source, permit): (ssh_core::transfer::Reader, _) = match source {
            Some(snapshot) => (snapshot.reader(), permit),
            None => {
                let local = Arc::clone(self);
                let uri = uri.to_owned();
                let (file, permit) = tokio::task::spawn_blocking(move || {
                    // Keep admission charged if cancellation leaves this open in progress.
                    local.open_input(&uri).map(|file| (file, permit))
                })
                .await
                .map_err(std::io::Error::other)??;
                (Box::new(tokio::fs::File::from_std(file)), permit)
            }
        };
        let disk = crate::disk::allocate(staging, Some(permit), false).await?;
        let snapshot = crate::disk::receive(disk, &mut source, limit)
            .await
            .map_err(|error| std::io::Error::other(error.message()))?;
        Ok(PreparedUpload::from_reader(
            snapshot.identity(uri.to_owned()),
            snapshot.reader(),
        ))
    }

    fn open_input(&self, uri: &str) -> std::io::Result<File> {
        let uri = url::Url::parse(uri).map_err(|_| std::io::Error::other("invalid file URI"))?;
        if uri.scheme() != "file" || uri.query().is_some() || uri.fragment().is_some() {
            return Err(std::io::Error::other("a local file URI is required"));
        }
        let path = uri
            .to_file_path()
            .map_err(|()| std::io::Error::other("invalid local file URI"))?;
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| std::io::Error::other("file is outside the shared directory"))?;
        let mut components = relative.components().peekable();
        let mut file = self.root_fd.try_clone()?;
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(std::io::Error::other("invalid file path component"));
            };
            let mut flags =
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
            if components.peek().is_some() {
                flags |= OFlag::O_DIRECTORY;
            }
            file = File::from(openat(&file, name, flags, Mode::empty())?);
        }
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("input is not a regular file"));
        }
        Ok(file)
    }

    pub fn staging(&self) -> std::io::Result<Arc<File>> {
        Ok(Arc::new(self.output.fd.try_clone()?))
    }

    pub fn publish(
        &self,
        name: &str,
        snapshot: &Arc<crate::disk::Snapshot>,
    ) -> std::io::Result<OwnedFile> {
        validate_name(name)?;
        snapshot.disk.publish(&self.output.fd, name)?;
        Ok(OwnedFile {
            directory: Arc::clone(&self.output),
            name: name.to_owned(),
        })
    }
}

impl OwnedFile {
    pub fn remove(&self) -> std::io::Result<()> {
        match unlinkat(
            &self.directory.fd,
            self.name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        ) {
            Ok(()) | Err(nix::errno::Errno::ENOENT) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for OwnedFile {
    fn drop(&mut self) {
        if let Err(error) = unlinkat(
            &self.directory.fd,
            self.name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        ) && error != nix::errno::Errno::ENOENT
        {
            tracing::warn!(%error, "could not remove staged output file");
        }
    }
}
impl Drop for OutputDirectory {
    fn drop(&mut self) {
        if let Err(error) = unlinkat(&self.parent, self.name.as_str(), UnlinkatFlags::RemoveDir) {
            tracing::warn!(%error, "could not remove output staging directory");
        }
    }
}

fn validate_name(name: &str) -> std::io::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(std::io::Error::other("invalid generated file name"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("ssh-local-files-{}", rand::random::<u64>()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn uri(&self, name: &str) -> String {
            url::Url::from_file_path(self.0.join(name))
                .unwrap()
                .to_string()
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[tokio::test]
    async fn large_local_snapshots_publish_without_copying_the_disk_contents() {
        use std::os::unix::fs::MetadataExt as _;
        let root = Scratch::new();
        let input = std::fs::File::create(root.0.join("large")).unwrap();
        let size = 17 * 1024 * 1024;
        input.set_len(size).unwrap();
        let local = Arc::new(LocalFiles::new(&root.0).unwrap());
        let upload = local
            .read(&root.uri("large"), local.staging().unwrap(), size)
            .await
            .unwrap();
        assert_eq!(upload.identity().bytes, size);
        assert!(
            local
                .read(
                    &root.uri("large"),
                    local.staging().unwrap(),
                    size.saturating_sub(1)
                )
                .await
                .is_err()
        );
        let disk = crate::disk::allocate(local.staging().unwrap(), None, true)
            .await
            .unwrap();
        let snapshot = crate::disk::receive(
            disk,
            &mut tokio::fs::File::open(root.0.join("large")).await.unwrap(),
            size,
        )
        .await
        .unwrap();
        let staged_inode = std::fs::read_dir(&local.output.path)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .metadata()
            .unwrap()
            .ino();
        let file = local.publish("largeoutput", &snapshot).unwrap();
        let published = local.output.path.join("largeoutput");
        assert_eq!(std::fs::metadata(&published).unwrap().len(), size);
        let inode = std::fs::metadata(&published).unwrap().ino();
        assert_eq!(inode, staged_inode);
        // Renaming consumes the staging name; no second full file remains beside the output.
        assert_eq!(std::fs::read_dir(&local.output.path).unwrap().count(), 1);
        drop(file);
        assert!(!published.exists());
    }

    #[tokio::test]
    async fn local_inputs_are_regular_files_within_the_shared_root_and_are_snapshotted() {
        let root = Scratch::new();
        let outside = Scratch::new();
        std::fs::write(root.0.join("input"), [0, 255, 1]).unwrap();
        std::fs::write(outside.0.join("secret"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.0.join("secret"), root.0.join("link")).unwrap();
        std::os::unix::fs::symlink(&outside.0, root.0.join("directory-link")).unwrap();
        let local = Arc::new(LocalFiles::new(&root.0).unwrap());
        let original = local
            .read(
                &root.uri("input"),
                crate::disk::directory(&root.0).unwrap(),
                100,
            )
            .await
            .unwrap();
        std::fs::write(root.0.join("input"), b"changed").unwrap();
        assert_eq!(original.identity().bytes, 3);
        assert_ne!(
            original.identity().sha256,
            local
                .read(
                    &root.uri("input"),
                    crate::disk::directory(&root.0).unwrap(),
                    100
                )
                .await
                .unwrap()
                .identity()
                .sha256
        );
        for uri in [
            root.uri("link"),
            root.uri("directory-link/secret"),
            outside.uri("secret"),
            "data:text/plain,content".to_owned(),
        ] {
            assert!(
                local
                    .read(&uri, crate::disk::directory(&root.0).unwrap(), 100)
                    .await
                    .is_err(),
                "accepted {uri}"
            );
        }
    }

    #[tokio::test]
    async fn output_publication_is_complete_private_and_cleans_up_only_owned_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = Scratch::new();
        std::fs::write(root.0.join("input"), b"user input").unwrap();
        let local = Arc::new(LocalFiles::new(&root.0).unwrap());
        let bytes = [0, 255, 254, 10];
        let snapshot = crate::disk::receive(
            crate::disk::allocate(crate::disk::directory(&root.0).unwrap(), None, true)
                .await
                .unwrap(),
            &mut std::io::Cursor::new(bytes),
            100,
        )
        .await
        .unwrap();
        let file = local.publish("output", &snapshot).unwrap();
        let path = url::Url::parse(&local.uri("output").unwrap())
            .unwrap()
            .to_file_path()
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(file);
        assert!(!path.exists());
        let collision = local.output.path.join("collision");
        std::fs::write(&collision, b"preserve").unwrap();
        let replacement = crate::disk::receive(
            crate::disk::allocate(local.staging().unwrap(), None, true)
                .await
                .unwrap(),
            &mut std::io::Cursor::new(b"new"),
            100,
        )
        .await
        .unwrap();
        assert!(local.publish("collision", &replacement).is_err());
        drop(replacement);
        assert_eq!(std::fs::read(&collision).unwrap(), b"preserve");
        std::fs::remove_file(collision).unwrap();
        let staging = local.output.path.clone();
        drop(local);
        assert!(!staging.exists());
        assert_eq!(std::fs::read(root.0.join("input")).unwrap(), b"user input");
    }
}
