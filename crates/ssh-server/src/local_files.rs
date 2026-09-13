//! Stdio file references resolve inside an operator-configured shared directory.

use nix::fcntl::{OFlag, RenameFlags, openat, renameat2};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use ssh_core::{files::MAX_TRANSFER_BYTES, transfer::PreparedUpload};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

pub struct LocalFiles {
    root: PathBuf,
    root_fd: File,
    output: Arc<OutputDirectory>,
    active: Mutex<Vec<Weak<[u8]>>>,
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
            active: Mutex::new(Vec::new()),
        })
    }

    pub fn uri(&self, name: &str) -> std::io::Result<String> {
        validate_name(name)?;
        url::Url::from_file_path(self.output.path.join(name))
            .map(String::from)
            .map_err(|()| std::io::Error::other("output path cannot be represented as a file URI"))
    }

    pub fn read(&self, uri: &str) -> std::io::Result<PreparedUpload> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        active.retain(|bytes| bytes.strong_count() > 0);
        if active.len() >= 16 {
            return Err(std::io::Error::other("local input capacity is exhausted"));
        }
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
        let mut bytes = Vec::new();
        file.take((MAX_TRANSFER_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_TRANSFER_BYTES {
            return Err(std::io::Error::other("input exceeds the transfer limit"));
        }
        let bytes: Arc<[u8]> = bytes.into();
        active.push(Arc::downgrade(&bytes));
        PreparedUpload::from_shared(uri.to_string(), bytes).map_err(std::io::Error::other)
    }

    pub fn publish(&self, name: &str, bytes: &[u8]) -> std::io::Result<OwnedFile> {
        validate_name(name)?;
        let partial = format!("{name}.partial");
        let mut file = File::from(openat(
            &self.output.fd,
            partial.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?);
        let mut owned = OwnedFile {
            directory: Arc::clone(&self.output),
            name: partial,
        };
        file.write_all(bytes)?;
        drop(file);
        renameat2(
            &self.output.fd,
            owned.name.as_str(),
            &self.output.fd,
            name,
            RenameFlags::RENAME_NOREPLACE,
        )?;
        owned.name = name.to_owned();
        Ok(owned)
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

    #[test]
    fn local_inputs_are_regular_files_within_the_shared_root_and_are_snapshotted() {
        let root = Scratch::new();
        let outside = Scratch::new();
        std::fs::write(root.0.join("input"), [0, 255, 1]).unwrap();
        std::fs::write(outside.0.join("secret"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.0.join("secret"), root.0.join("link")).unwrap();
        std::os::unix::fs::symlink(&outside.0, root.0.join("directory-link")).unwrap();
        let local = LocalFiles::new(&root.0).unwrap();
        let original = local.read(&root.uri("input")).unwrap();
        std::fs::write(root.0.join("input"), b"changed").unwrap();
        assert_eq!(original.identity().bytes, 3);
        assert_ne!(
            original.identity().sha256,
            local.read(&root.uri("input")).unwrap().identity().sha256
        );
        for uri in [
            root.uri("link"),
            root.uri("directory-link/secret"),
            outside.uri("secret"),
            "data:text/plain,content".to_owned(),
        ] {
            assert!(local.read(&uri).is_err(), "accepted {uri}");
        }
    }

    #[test]
    fn output_publication_is_complete_private_and_cleans_up_only_owned_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = Scratch::new();
        std::fs::write(root.0.join("input"), b"user input").unwrap();
        let local = LocalFiles::new(&root.0).unwrap();
        let bytes = [0, 255, 254, 10];
        let file = local.publish("output", &bytes).unwrap();
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
        let collision = local.output.path.join("collision.partial");
        std::fs::write(&collision, b"preserve").unwrap();
        assert!(local.publish("collision", b"new").is_err());
        assert_eq!(std::fs::read(&collision).unwrap(), b"preserve");
        std::fs::remove_file(collision).unwrap();
        let staging = local.output.path.clone();
        drop(local);
        assert!(!staging.exists());
        assert_eq!(std::fs::read(root.0.join("input")).unwrap(), b"user input");
    }
}
