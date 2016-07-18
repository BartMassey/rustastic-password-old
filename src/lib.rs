// Copyright 2014 The Rustastic Password Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::Result as IoResult;

#[cfg(not(windows))]
mod unix {
    extern crate termios;
    extern crate libc;

    use std::io::{ BufReader, BufRead, Error, ErrorKind, Write };
    use std::io::Result as IoResult;
    use std::ptr;
    use std::fs::{ File, OpenOptions };
    use std::os::unix::io::*;
    use self::libc::{ STDERR_FILENO, isatty };
    use self::termios::*;

    fn get_tty(writable: bool) -> IoResult<File> {
        match OpenOptions::new().read(true).write(writable).open("/dev/tty") {
            Err(_) => match unsafe { isatty(STDERR_FILENO) } {
                0 => Err(Error::new(ErrorKind::NotFound, "no tty")),
                _ => unsafe {
                    return Ok(FromRawFd::from_raw_fd(STDERR_FILENO))
                }
            },
            f => f
        }
    }

    pub fn read_password_opt_prompt(opt_prompt: Option<String>) -> IoResult<String> {
        // Get a tty.
        let mut tty = match get_tty(opt_prompt.is_some()) {
            Ok(f) => f,
            Err(e) => return Err(e)
        };

        // Print any prompt.
        match opt_prompt {
            Some(prompt) => {
                try!(tty.write(prompt.as_bytes()));
                try!(tty.flush());
            },
            None => ()
        };

        // Make two copies of the terminal settings. The first one will be modified
        // and the second one will act as a backup for when we want to set the
        // terminal back to its original state.
        let fd = tty.as_raw_fd();
        let mut term = try!(Termios::from_fd(fd));
        let term_orig = term;

        // Hide the password. This is what makes this function useful.
        term.c_lflag &= !ECHO;

        // But don't hide the NL character when the user hits ENTER.
        term.c_lflag |= ECHONL;

        // Save the settings for now.
        try!(tcsetattr(fd, TCSANOW, &term));

        // Read the password.
        let mut password = String::new();
        let mut reader = BufReader::new(tty);
        match reader.read_line(&mut password) {
            Ok(_) => { },
            Err(err) => {
                // Reset the terminal and quit.
                try!(tcsetattr(fd, TCSANOW, &term_orig));

                // Return the original IoError.
                return Err(err);
            }
        };

        // Reset the terminal and quit.
        match tcsetattr(fd, TCSANOW, &term_orig) {
            Ok(_) => {},
            Err(err) => {
                unsafe {
                    let pw = password.as_mut_vec();
                    ptr::write_bytes(pw.as_mut_ptr(), 0, pw.len());
                }
                return Err(err);
            }
        }

        // Remove the \n from the line.
        match password.pop() {
            Some(_) => {},
            None => { return Err(Error::new(ErrorKind::UnexpectedEof, "unexpected end of file")) }
        };

        Ok(password)
    }

    #[test]
    fn it_works() {
    }
}

#[cfg(windows)]
mod windows {
    extern crate winapi;
    extern crate kernel32;
    use std::io::{ Error, ErrorKind, stderr, Write };
    use std::io::Result as IoResult;
    use std::ptr::null_mut;

    pub fn read_password_opt_prompt(opt_prompt: Option<String>) -> IoResult<String> {
        // Print any prompt.
        match opt_prompt {
            Some(prompt) => {
                let mut serr = stderr();
                try!(serr.write(prompt.as_bytes()));
                try!(serr.flush());
            },
            None => ()
        };
        // Get the stdin handle
        let handle = unsafe { kernel32::GetStdHandle(winapi::STD_INPUT_HANDLE) };
        if handle == winapi::INVALID_HANDLE_VALUE {
            return Err(Error::last_os_error())
        }
        let mut mode = 0;
        // Get the old mode so we can reset back to it when we are done
        if unsafe { kernel32::GetConsoleMode(handle, &mut mode as winapi::LPDWORD) } == 0 {
            return Err(Error::last_os_error())
        }
        // We want to be able to read line by line, and we still want backspace to work
        if unsafe { kernel32::SetConsoleMode(
            handle, winapi::ENABLE_LINE_INPUT | winapi::ENABLE_PROCESSED_INPUT,
        ) } == 0 {
            return Err(Error::last_os_error())
        }
        // If your password is over 0x1000 characters you have paranoia problems
        let mut buf: [winapi::WCHAR; 0x1000] = [0; 0x1000];
        let mut read = 0;
        // Read a line of stuff from the console
        if unsafe { kernel32::ReadConsoleW(
            handle, buf.as_mut_ptr() as winapi::LPVOID, 0x1000,
            &mut read, null_mut(),
        ) } == 0 {
            let err = Error::last_os_error();
            // Even if we failed to read we should still try to set the mode back
            unsafe { kernel32::SetConsoleMode(handle, mode) };
            return Err(err)
        }
        // Set the the mode back to normal
        if unsafe { kernel32::SetConsoleMode(handle, mode) } == 0 {
            return Err(Error::last_os_error())
        }
        // Since the newline isn't echo'd we need to do it ourselves
        println!("");
        // Subtract 2 to get rid of \r\n
        match String::from_utf16(&buf[..read as usize - 2]) {
            Ok(s) => Ok(s),
            Err(_) => Err(Error::new(ErrorKind::InvalidInput, "invalid UTF-16")),
        }
    }
}

#[cfg(not(windows))]
use unix::read_password_opt_prompt;
#[cfg(windows)]
use windows::read_password_opt_prompt;

/// Prompts with the given prompt, then reads a "password"
/// from the user's terminal without echoing that password
/// on the screen.
///
/// On UNIX, the prompt is written and the password read
/// from `/dev/tty` if possible, else from `stderr` (file
/// descriptor 2) if possible, else `read_password_prompt()`
/// fails. On Windows, the prompt is written to `stderr` and
/// the password is read from `stdin`.
///
/// # Examples
///
/// ```rust,no_run
/// extern crate rpassword;
/// 
/// let pw = rpassword::read_password_prompt("Password: ").unwrap();
///    
/// ```
pub fn read_password_prompt<S>(prompt: S) -> IoResult<String>
    where S: Into<String> {
        read_password_opt_prompt(Some(prompt.into()))
    }

/// Reads a "password" from the user's terminal without
/// echoing that password on the screen.
///
/// On UNIX, the prompt the password is read
/// from `/dev/tty` if possible, else from `stderr` (file
/// descriptor 2) if possible, else `read_password_prompt()`
/// fails. On Windows, the password is read from `stdin`.
///
/// # Examples
///
/// ```rust,no_run
/// extern crate rpassword;
/// 
/// let pw = rpassword::read_password().unwrap();
///    
/// ```
pub fn read_password() -> IoResult<String> {
    read_password_opt_prompt(None)
}

