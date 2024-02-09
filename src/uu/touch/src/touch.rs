// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

// spell-checker:ignore (ToDO) filetime datetime lpszfilepath mktime DATETIME datelike timelike
// spell-checker:ignore (FORMATS) MMDDhhmm YYYYMMDDHHMM YYMMDDHHMM YYYYMMDDHHMMS

pub mod error;

use chrono::{
    DateTime, Datelike, Duration, Local, LocalResult, NaiveDate, NaiveDateTime, NaiveTime,
    TimeZone, Timelike,
};
use clap::builder::ValueParser;
use clap::{crate_version, Arg, ArgAction, ArgGroup, ArgMatches, Command};
use filetime::{set_file_times, set_symlink_file_times, FileTime};
use std::borrow::Cow;
use std::ffi::OsString;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use uucore::display::Quotable;
use uucore::error::{UResult, USimpleError};
use uucore::{format_usage, help_about, help_usage};

use crate::error::TouchError;

/// Options contains all the possible behaviors and flags for touch.
///
/// All options are public so that the options can be programmatically
/// constructed by other crates, such as nushell. That means that this struct is
/// part of our public API. It should therefore not be changed without good reason.
///
/// The fields are documented with the arguments that determine their value.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Options {
    /// Do not create any files. Set by `-c`/`--no-create`.
    pub no_create: bool,

    /// Affect each symbolic link instead of any referenced file. Set by `-h`/`--no-dereference`.
    pub no_deref: bool,

    /// The access time to set to (`None` to not update).
    /// To convert a [DateTime] to a [FileTime], see [datetime_to_filetime].
    /// To get the access time of a file, see [stat].
    pub atime: Option<FileTime>,

    /// The modification time to set to (`None` to not update).
    /// To convert a [DateTime] to a [FileTime], see [datetime_to_filetime].
    /// To get the modification time of a file, see [stat].
    pub mtime: Option<FileTime>,
}

pub enum InputFile {
    /// A regular file
    Path(PathBuf),
    /// Touch stdout. `--no-dereference` will be ignored in this case.
    Stdout,
}

const ABOUT: &str = help_about!("touch.md");
const USAGE: &str = help_usage!("touch.md");

pub mod options {
    // Both SOURCES and sources are needed as we need to be able to refer to the ArgGroup.
    pub static SOURCES: &str = "sources";
    pub mod sources {
        pub static DATE: &str = "date";
        pub static REFERENCE: &str = "reference";
        pub static TIMESTAMP: &str = "timestamp";
    }
    pub static HELP: &str = "help";
    pub static ACCESS: &str = "access";
    pub static MODIFICATION: &str = "modification";
    pub static NO_CREATE: &str = "no-create";
    pub static NO_DEREF: &str = "no-dereference";
    pub static TIME: &str = "time";
}

static ARG_FILES: &str = "files";

mod format {
    pub(crate) const POSIX_LOCALE: &str = "%a %b %e %H:%M:%S %Y";
    pub(crate) const ISO_8601: &str = "%Y-%m-%d";
    // "%Y%m%d%H%M.%S" 15 chars
    pub(crate) const YYYYMMDDHHMM_DOT_SS: &str = "%Y%m%d%H%M.%S";
    // "%Y-%m-%d %H:%M:%S.%SS" 12 chars
    pub(crate) const YYYYMMDDHHMMSS: &str = "%Y-%m-%d %H:%M:%S.%f";
    // "%Y-%m-%d %H:%M:%S" 12 chars
    pub(crate) const YYYYMMDDHHMMS: &str = "%Y-%m-%d %H:%M:%S";
    // "%Y-%m-%d %H:%M" 12 chars
    // Used for example in tests/touch/no-rights.sh
    pub(crate) const YYYY_MM_DD_HH_MM: &str = "%Y-%m-%d %H:%M";
    // "%Y%m%d%H%M" 12 chars
    pub(crate) const YYYYMMDDHHMM: &str = "%Y%m%d%H%M";
    // "%Y-%m-%d %H:%M +offset"
    // Used for example in tests/touch/relative.sh
    pub(crate) const YYYYMMDDHHMM_OFFSET: &str = "%Y-%m-%d %H:%M %z";
}

/// Convert a DateTime with a TZ offset into a FileTime
///
/// The DateTime is converted into a unix timestamp from which the FileTime is
/// constructed.
pub fn datetime_to_filetime<T: TimeZone>(dt: &DateTime<T>) -> FileTime {
    FileTime::from_unix_time(dt.timestamp(), dt.timestamp_subsec_nanos())
}

fn filetime_to_datetime(ft: &FileTime) -> Option<DateTime<Local>> {
    Some(DateTime::from_timestamp(ft.unix_seconds(), ft.nanoseconds())?.into())
}

#[uucore::main]
pub fn uumain(args: impl uucore::Args) -> UResult<()> {
    let matches = uu_app().try_get_matches_from(args)?;

    let files: Vec<OsString> = matches
        .get_many::<OsString>(ARG_FILES)
        .ok_or_else(|| {
            USimpleError::new(
                1,
                format!(
                    "missing file operand\nTry '{} --help' for more information.",
                    uucore::execution_phrase()
                ),
            )
        })?
        .cloned()
        .collect();

    let (change_atime, change_mtime) = determine_atime_mtime_change(&matches);

    let no_deref = matches.get_flag(options::NO_DEREF);

    let reference = matches.get_one::<OsString>(options::sources::REFERENCE);
    let date = matches.get_one::<String>(options::sources::DATE);
    let timestamp = matches.get_one::<String>(options::sources::TIMESTAMP);

    let (atime, mtime) = match reference {
        Some(reference) => determine_times_from_ref(Path::new(reference), date, no_deref)?,
        None => {
            let time = if let Some(date) = date {
                parse_date(Local::now(), date)?
            } else if let Some(ts) = timestamp {
                parse_timestamp(ts)?
            } else {
                datetime_to_filetime(&Local::now())
            };
            (time, time)
        }
    };

    let opts = Options {
        no_create: matches.get_flag(options::NO_CREATE),
        no_deref,
        atime: if change_atime { Some(atime) } else { None },
        mtime: if change_mtime { Some(mtime) } else { None },
    };

    for filename in files {
        let input = if filename == "-" {
            InputFile::Stdout
        } else {
            InputFile::Path(PathBuf::from(filename))
        };
        touch(&input, &opts)?;
    }

    Ok(())
}

pub fn uu_app() -> Command {
    Command::new(uucore::util_name())
        .version(crate_version!())
        .about(ABOUT)
        .override_usage(format_usage(USAGE))
        .infer_long_args(true)
        .disable_help_flag(true)
        .arg(
            Arg::new(options::HELP)
                .long(options::HELP)
                .help("Print help information.")
                .action(ArgAction::Help),
        )
        .arg(
            Arg::new(options::ACCESS)
                .short('a')
                .help("change only the access time")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::sources::TIMESTAMP)
                .short('t')
                .help("use [[CC]YY]MMDDhhmm[.ss] instead of the current time")
                .value_name("STAMP"),
        )
        .arg(
            Arg::new(options::sources::DATE)
                .short('d')
                .long(options::sources::DATE)
                .allow_hyphen_values(true)
                .help("parse argument and use it instead of current time")
                .value_name("STRING")
                .conflicts_with(options::sources::TIMESTAMP),
        )
        .arg(
            Arg::new(options::MODIFICATION)
                .short('m')
                .help("change only the modification time")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::NO_CREATE)
                .short('c')
                .long(options::NO_CREATE)
                .help("do not create any files")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::NO_DEREF)
                .short('h')
                .long(options::NO_DEREF)
                .help(
                    "affect each symbolic link instead of any referenced file \
                     (only for systems that can change the timestamps of a symlink)",
                )
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new(options::sources::REFERENCE)
                .short('r')
                .long(options::sources::REFERENCE)
                .help("use this file's times instead of the current time")
                .value_name("FILE")
                .value_parser(ValueParser::os_string())
                .value_hint(clap::ValueHint::AnyPath)
                .conflicts_with(options::sources::TIMESTAMP),
        )
        .arg(
            Arg::new(options::TIME)
                .long(options::TIME)
                .help(
                    "change only the specified time: \"access\", \"atime\", or \
                     \"use\" are equivalent to -a; \"modify\" or \"mtime\" are \
                     equivalent to -m",
                )
                .value_name("WORD")
                .value_parser(["access", "atime", "use", "modify", "mtime"]),
        )
        .arg(
            Arg::new(ARG_FILES)
                .action(ArgAction::Append)
                .num_args(1..)
                .value_parser(ValueParser::os_string())
                .value_hint(clap::ValueHint::AnyPath),
        )
        .group(
            ArgGroup::new(options::SOURCES)
                .args([
                    options::sources::TIMESTAMP,
                    options::sources::DATE,
                    options::sources::REFERENCE,
                ])
                .multiple(true),
        )
}

/// Determine the access and modification time from a reference file
fn determine_times_from_ref(
    reference: &Path,
    date: Option<&String>,
    no_deref: bool,
) -> Result<(FileTime, FileTime), TouchError> {
    if let Some(date) = date {
        let (atime, mtime) = stat(reference, !no_deref)?;
        let atime = filetime_to_datetime(&atime)
            .ok_or_else(|| TouchError::InvalidFiletime(reference.to_owned(), atime))?;
        let mtime = filetime_to_datetime(&mtime)
            .ok_or_else(|| TouchError::InvalidFiletime(reference.to_owned(), mtime))?;
        Ok((parse_date(atime, date)?, parse_date(mtime, date)?))
    } else {
        stat(reference, !no_deref)
    }
}

/// Execute the touch command.
///
/// # Errors
///
/// If the user doesn't have permission to access the file, or if one of the directory
/// components of the file path doesn't exist
pub fn touch(file: &InputFile, opts: &Options) -> Result<(), TouchError> {
    let (path, is_stdout) = match file {
        InputFile::Stdout => (Cow::Owned(pathbuf_from_stdout()?), true),
        InputFile::Path(path) => (Cow::Borrowed(path), false),
    };
    let path = path.as_path();

    let metadata_result = if opts.no_deref {
        path.symlink_metadata()
    } else {
        path.metadata()
    };

    if let Err(e) = metadata_result {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(TouchError::CannotReadAttributes(path.to_owned(), e.kind()));
        }

        if opts.no_create {
            return Ok(());
        }

        if opts.no_deref {
            return Err(TouchError::TargetFileNotFound(path.to_owned()));
        }

        if let Err(e) = File::create(path) {
            return Err(TouchError::CannotCreate(path.to_owned(), e.kind()));
        };
    }

    update_times(path, is_stdout, opts)
}

/// Returns whether atime and mtime are to be changed.
/// Note: If none of `-a`, `-m`, and `--time` are passed, the result is `(true, true)`, not `(false, false)`
fn determine_atime_mtime_change(matches: &ArgMatches) -> (bool, bool) {
    // If `--time` is given, Some(true) if equivalent to `-a`, Some(false) if equivalent to `-m`
    // If `--time` not given, Nones
    let time_access_only = if matches.contains_id(options::TIME) {
        matches
            .get_one::<String>(options::TIME)
            .map(|time| time.contains("access") || time.contains("atime") || time.contains("use"))
    } else {
        None
    };

    let atime_only = matches.get_flag(options::ACCESS) || time_access_only.unwrap_or_default();
    let mtime_only = matches.get_flag(options::MODIFICATION) || !time_access_only.unwrap_or(true);

    // Note that "-a" and "-m" may be passed together; this is not an xor.
    (atime_only || !mtime_only, mtime_only || !atime_only)
}

// Updating file access and modification times based on user-specified options
fn update_times(path: &Path, is_stdout: bool, opts: &Options) -> Result<(), TouchError> {
    let (atime, mtime) = match (opts.atime, opts.mtime) {
        (Some(atime), Some(mtime)) => (atime, mtime),
        _ => {
            // If changing "only" atime or mtime, grab the existing value of the other.
            // It's necessary to get the metadata here because although atime and mtime
            // can be set separately for normal files, filetime doesn't expose functions
            // to set them separately for symlinks
            let st = stat(path, !opts.no_deref)?;
            (opts.atime.unwrap_or(st.0), opts.mtime.unwrap_or(st.1))
        }
    };

    // sets the file access and modification times for a file or a symbolic link.
    // The filename, access time (atime), and modification time (mtime) are provided as inputs.

    // If the filename is not "-", indicating a special case for touch -h -,
    // the code checks if the NO_DEREF flag is set, which means the user wants to
    // set the times for a symbolic link itself, rather than the file it points to.
    if opts.no_deref && !is_stdout {
        set_symlink_file_times(path, atime, mtime)
    } else {
        set_file_times(path, atime, mtime)
    }
    .map_err(|e| TouchError::CannotSetAttributes(path.to_owned(), e.kind()))
}

// Get metadata of the provided path
// If `follow` is `true`, the function will try to follow symlinks
// If `follow` is `false` or the symlink is broken, the function will return metadata of the symlink itself
pub fn stat(path: &Path, follow: bool) -> Result<(FileTime, FileTime), TouchError> {
    let metadata = if follow {
        fs::metadata(path).or_else(|_| fs::symlink_metadata(path))
    } else {
        fs::symlink_metadata(path)
    }
    .map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            TouchError::ReferenceFileNotFound(path.to_owned())
        } else {
            TouchError::CannotReadAttributes(path.to_owned(), e.kind())
        }
    })?;

    Ok((
        FileTime::from_last_access_time(&metadata),
        FileTime::from_last_modification_time(&metadata),
    ))
}

fn parse_date(ref_time: DateTime<Local>, s: &str) -> Result<FileTime, TouchError> {
    // This isn't actually compatible with GNU touch, but there doesn't seem to
    // be any simple specification for what format this parameter allows and I'm
    // not about to implement GNU parse_datetime.
    // http://git.savannah.gnu.org/gitweb/?p=gnulib.git;a=blob_plain;f=lib/parse-datetime.y

    // TODO: match on char count?

    // "The preferred date and time representation for the current locale."
    // "(In the POSIX locale this is equivalent to %a %b %e %H:%M:%S %Y.)"
    // time 0.1.43 parsed this as 'a b e T Y'
    // which is equivalent to the POSIX locale: %a %b %e %H:%M:%S %Y
    // Tue Dec  3 ...
    // ("%c", POSIX_LOCALE_FORMAT),
    //
    if let Ok(parsed) = NaiveDateTime::parse_from_str(s, format::POSIX_LOCALE) {
        return Ok(datetime_to_filetime(&parsed.and_utc()));
    }

    // Also support other formats found in the GNU tests like
    // in tests/misc/stat-nanoseconds.sh
    // or tests/touch/no-rights.sh
    for fmt in [
        format::YYYYMMDDHHMMS,
        format::YYYYMMDDHHMMSS,
        format::YYYY_MM_DD_HH_MM,
        format::YYYYMMDDHHMM_OFFSET,
    ] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(s, fmt) {
            return Ok(datetime_to_filetime(&parsed.and_utc()));
        }
    }

    // "Equivalent to %Y-%m-%d (the ISO 8601 date format). (C99)"
    // ("%F", ISO_8601_FORMAT),
    if let Ok(parsed_date) = NaiveDate::parse_from_str(s, format::ISO_8601) {
        let parsed = Local
            .from_local_datetime(&parsed_date.and_time(NaiveTime::MIN))
            .unwrap();
        return Ok(datetime_to_filetime(&parsed));
    }

    // "@%s" is "The number of seconds since the Epoch, 1970-01-01 00:00:00 +0000 (UTC). (TZ) (Calculated from mktime(tm).)"
    if s.bytes().next() == Some(b'@') {
        if let Ok(ts) = &s[1..].parse::<i64>() {
            return Ok(FileTime::from_unix_time(*ts, 0));
        }
    }

    if let Ok(dt) = parse_datetime::parse_datetime_at_date(ref_time, s) {
        return Ok(datetime_to_filetime(&dt));
    }

    Err(TouchError::InvalidDateFormat(s.to_owned()))
}

fn parse_timestamp(s: &str) -> UResult<FileTime> {
    use format::*;

    let current_year = || Local::now().year();

    let (format, ts) = match s.chars().count() {
        15 => (YYYYMMDDHHMM_DOT_SS, s.to_owned()),
        12 => (YYYYMMDDHHMM, s.to_owned()),
        // If we don't add "20", we have insufficient information to parse
        13 => (YYYYMMDDHHMM_DOT_SS, format!("20{}", s)),
        10 => (YYYYMMDDHHMM, format!("20{}", s)),
        11 => (YYYYMMDDHHMM_DOT_SS, format!("{}{}", current_year(), s)),
        8 => (YYYYMMDDHHMM, format!("{}{}", current_year(), s)),
        _ => {
            return Err(USimpleError::new(
                1,
                format!("invalid date format {}", s.quote()),
            ))
        }
    };

    let local = NaiveDateTime::parse_from_str(&ts, format)
        .map_err(|_| USimpleError::new(1, format!("invalid date ts format {}", ts.quote())))?;
    let mut local = match chrono::Local.from_local_datetime(&local) {
        LocalResult::Single(dt) => dt,
        _ => {
            return Err(USimpleError::new(
                1,
                format!("invalid date ts format {}", ts.quote()),
            ))
        }
    };

    // Chrono caps seconds at 59, but 60 is valid. It might be a leap second
    // or wrap to the next minute. But that doesn't really matter, because we
    // only care about the timestamp anyway.
    // Tested in gnu/tests/touch/60-seconds
    if local.second() == 59 && ts.ends_with(".60") {
        local += Duration::seconds(1);
    }

    // Due to daylight saving time switch, local time can jump from 1:59 AM to
    // 3:00 AM, in which case any time between 2:00 AM and 2:59 AM is not
    // valid. If we are within this jump, chrono takes the offset from before
    // the jump. If we then jump forward an hour, we get the new corrected
    // offset. Jumping back will then now correctly take the jump into account.
    let local2 = local + Duration::hours(1) - Duration::hours(1);
    if local.hour() != local2.hour() {
        return Err(USimpleError::new(
            1,
            format!("invalid date format {}", s.quote()),
        ));
    }

    Ok(datetime_to_filetime(&local))
}

// TODO: this may be a good candidate to put in fsext.rs
/// Returns a PathBuf to stdout.
///
/// On Windows, uses GetFinalPathNameByHandleW to attempt to get the path
/// from the stdout handle.
fn pathbuf_from_stdout() -> Result<PathBuf, TouchError> {
    #[cfg(all(unix, not(target_os = "android")))]
    {
        Ok(PathBuf::from("/dev/stdout"))
    }
    #[cfg(target_os = "android")]
    {
        Ok(PathBuf::from("/proc/self/fd/1"))
    }
    #[cfg(windows)]
    {
        use std::os::windows::prelude::AsRawHandle;
        use windows_sys::Win32::Foundation::{
            GetLastError, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_PATH_NOT_FOUND,
            HANDLE, MAX_PATH,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            GetFinalPathNameByHandleW, FILE_NAME_OPENED,
        };

        let handle = std::io::stdout().lock().as_raw_handle() as HANDLE;
        let mut file_path_buffer: [u16; MAX_PATH as usize] = [0; MAX_PATH as usize];

        // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlea#examples
        // SAFETY: We transmute the handle to be able to cast *mut c_void into a
        // HANDLE (i32) so rustc will let us call GetFinalPathNameByHandleW. The
        // reference example code for GetFinalPathNameByHandleW implies that
        // it is safe for us to leave lpszfilepath uninitialized, so long as
        // the buffer size is correct. We know the buffer size (MAX_PATH) at
        // compile time. MAX_PATH is a small number (260) so we can cast it
        // to a u32.
        let ret = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                file_path_buffer.as_mut_ptr(),
                file_path_buffer.len() as u32,
                FILE_NAME_OPENED,
            )
        };

        let buffer_size = match ret {
            ERROR_PATH_NOT_FOUND | ERROR_NOT_ENOUGH_MEMORY | ERROR_INVALID_PARAMETER => {
                return Err(TouchError::WindowsStdoutPathError(format!(
                    "GetFinalPathNameByHandleW failed with code {ret}"
                )))
            }
            0 => {
                return Err(TouchError::WindowsStdoutPathError(format!(
                    "GetFinalPathNameByHandleW failed with code {}",
                    // SAFETY: GetLastError is thread-safe and has no documented memory unsafety.
                    unsafe { GetLastError() },
                )));
            }
            e => e as usize,
        };

        // Don't include the null terminator
        Ok(String::from_utf16(&file_path_buffer[0..buffer_size])
            .map_err(|e| TouchError::WindowsStdoutPathError(e.to_string()))?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use crate::{determine_atime_mtime_change, uu_app};

    #[cfg(windows)]
    #[test]
    fn test_get_pathbuf_from_stdout_fails_if_stdout_is_not_a_file() {
        // We can trigger an error by not setting stdout to anything (will
        // fail with code 1)
        assert!(super::pathbuf_from_stdout()
            .expect_err("pathbuf_from_stdout should have failed")
            .to_string()
            .contains("GetFinalPathNameByHandleW failed with code 1"));
    }

    #[test]
    fn test_determine_atime_mtime_change() {
        assert_eq!(
            (true, true),
            determine_atime_mtime_change(&uu_app().try_get_matches_from(vec!["touch"]).unwrap())
        );
        assert_eq!(
            (true, true),
            determine_atime_mtime_change(
                &uu_app()
                    .try_get_matches_from(vec!["touch", "-a", "-m", "--time", "modify"])
                    .unwrap()
            )
        );
        assert_eq!(
            (true, false),
            determine_atime_mtime_change(
                &uu_app()
                    .try_get_matches_from(vec!["touch", "--time", "access"])
                    .unwrap()
            )
        );
        assert_eq!(
            (false, true),
            determine_atime_mtime_change(
                &uu_app().try_get_matches_from(vec!["touch", "-m"]).unwrap()
            )
        );
    }
}
