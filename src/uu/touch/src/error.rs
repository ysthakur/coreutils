// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

// spell-checker:ignore (misc) uioerror

use std::error::Error;
use std::fmt::{Display, Formatter, Result};
use std::path::PathBuf;

use filetime::FileTime;
use uucore::display::Quotable;
use uucore::error::UError;

/// An error encountered on a specific file
#[derive(Debug)]
pub enum TouchError {
    /// An error getting a path to stdout on Windows
    WindowsStdoutPathError(String),

    /// File exists already, but cannot read its metadata
    CannotGetTimes(Box<dyn UError>),

    /// Cannot set the file's access/modification times
    CannotSetTimes(Box<dyn UError>),

    /// File didn't exist and `-h`/`--no-dereference` was passed
    NotFound(Box<dyn UError>),

    /// Could not create the file
    CannotTouch(Box<dyn UError>),
}

impl Error for TouchError {}
impl UError for TouchError {}
impl Display for TouchError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            Self::WindowsStdoutPathError(code) => {
                write!(f, "GetFinalPathNameByHandleW failed with code {}", code)
            }
            Self::NotFound(error) => write!(f, "{}", error),
            Self::CannotTouch(error) => write!(f, "{}", error),
            Self::CannotGetTimes(error) => write!(f, "{}", error),
            Self::CannotSetTimes(error) => write!(f, "{}", error),
        }
    }
}

/// An error encountered when determining file access/modification times
#[derive(Debug)]
pub enum TimeError {
    // Date (passed with `--date`) was invalid
    InvalidDateFormat(String),

    /// The source [`FileTime`] couldn't be converted to a [`chrono::DateTime`]
    InvalidFiletime(FileTime),

    /// The reference file couldn't be found or its attributes couldn't be read
    ReferenceFileInaccessible(PathBuf, Box<dyn UError>),
}
impl Error for TimeError {}
impl UError for TimeError {}
impl Display for TimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::InvalidDateFormat(s) => write!(f, "Unable to parse date: {}", s),
            Self::InvalidFiletime(time) => write!(
                f,
                "Source has invalid access or modification time: {}",
                time,
            ),
            Self::ReferenceFileInaccessible(path, err) => {
                write!(f, "failed to get attributes of {}: {}", path.quote(), err)
            }
        }
    }
}
