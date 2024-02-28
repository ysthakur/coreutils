// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

// spell-checker:ignore (misc) uioerror

use std::error::Error;
use std::fmt::{Display, Formatter, Result};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use filetime::FileTime;
use uucore::display::Quotable;
use uucore::error::{UError, UIoError};

#[derive(Debug)]
pub enum TouchError {
    InvalidDateFormat(String),

    // TODO this doesn't say whether it was the access time or modification time that was invalid
    /// The reference file's time couldn't be converted to a [chrono::DateTime]
    InvalidFiletime(PathBuf, FileTime),

    /// The reference file's attributes could not be found or read
    ReferenceFileInaccessible(PathBuf, ErrorKind),

    /// An error getting a path to stdout on Windows
    WindowsStdoutPathError(String),

    TouchFileError {
        path: PathBuf,
        index: usize,
        error: TouchFileError,
    },
}

impl Error for TouchError {}
impl UError for TouchError {}
impl Display for TouchError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            Self::InvalidDateFormat(s) => write!(f, "Unable to parse date: {}", s),
            Self::InvalidFiletime(path, time) => write!(
                f,
                "Invalid access or modification time ({}) for reference file {}",
                time,
                path.quote()
            ),
            Self::ReferenceFileInaccessible(path, kind) => {
                write!(f, "failed to get attributes of {}: {}", path.quote(), kind)
            }
            Self::WindowsStdoutPathError(code) => {
                write!(f, "GetFinalPathNameByHandleW failed with code {}", code)
            }
            Self::TouchFileError { path, error, .. } => error.fmt(f, path),
        }
    }
}

/// An error encountered when touching a specific file
#[derive(Debug)]
pub enum TouchFileError {
    CannotCreate(std::io::Error),

    CannotReadTimes(std::io::Error),

    CannotSetTimes(std::io::Error),

    /// The target file could not be found (only applicable with `--no-dereference`)
    TargetFileNotFound,
}

impl TouchFileError {
    fn fmt(&self, f: &mut Formatter, path: &Path) -> Result {
        match self {
            Self::CannotCreate(err) => {
                write!(f, "cannot touch {}: {}", path.quote(), to_uioerror(err))
            }
            Self::CannotReadTimes(err) => {
                write!(
                    f,
                    "failed to get attributes of {}: {}",
                    path.quote(),
                    to_uioerror(err)
                )
            }
            Self::CannotSetTimes(err) => {
                write!(f, "setting times of {}: {}", path.quote(), to_uioerror(err))
            }
            Self::TargetFileNotFound => write!(
                f,
                "setting times of {}: No such file or directory",
                path.quote()
            ),
        }
    }
}

fn to_uioerror(err: &std::io::Error) -> UIoError {
    let copy = if let Some(code) = err.raw_os_error() {
        std::io::Error::from_raw_os_error(code)
    } else {
        std::io::Error::from(err.kind())
    };
    UIoError::from(copy)
}
