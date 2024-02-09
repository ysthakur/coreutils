// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
use std::error::Error;
use std::fmt::{Display, Formatter, Result};
use std::io::ErrorKind;
use std::path::PathBuf;

use filetime::FileTime;
use uucore::display::Quotable;
use uucore::error::UError;

#[derive(Debug)]
pub enum TouchError {
    CannotCreate(PathBuf, ErrorKind),

    CannotReadAttributes(PathBuf, ErrorKind),

    CannotSetAttributes(PathBuf, ErrorKind),

    InvalidDateFormat(String),

    // TODO this doesn't say whether it was the access time or modification time that was invalid
    /// The reference file's time couldn't be converted to a [chrono::DateTime]
    InvalidFiletime(PathBuf, FileTime),

    /// The reference file could not be found
    ReferenceFileNotFound(PathBuf),

    /// The target file could not be found (only applicable with `--no-dereference`)
    TargetFileNotFound(PathBuf),

    /// An error getting a path to stdout on Windows
    WindowsStdoutPathError(String),
}

impl Error for TouchError {}
impl UError for TouchError {}
impl Display for TouchError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            Self::CannotCreate(path, err_kind) => write!(
                f,
                "cannot touch {} because of IO error: {}",
                path.quote(),
                err_kind
            ),
            Self::CannotReadAttributes(path, kind) => {
                write!(f, "failed to get attributes of {}: {}", path.quote(), kind)
            }
            Self::CannotSetAttributes(path, kind) => {
                write!(f, "failed to set attributes of {}: {}", path.quote(), kind)
            }
            Self::InvalidDateFormat(s) => write!(f, "invalid date format {}", s.quote()),
            Self::InvalidFiletime(path, time) => write!(
                f,
                "Invalid access or modification time ({}) for reference file {}",
                time,
                path.quote()
            ),
            Self::ReferenceFileNotFound(path) => write!(f, "file not found: {}", path.quote()),
            Self::TargetFileNotFound(path) => write!(
                f,
                "setting times of {}: No such file or directory",
                path.quote()
            ),
            Self::WindowsStdoutPathError(code) => {
                write!(f, "GetFinalPathNameByHandleW failed with code {}", code)
            }
        }
    }
}
