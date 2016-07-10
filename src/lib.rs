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

    use std::io::{ BufReader, BufRead, Error, ErrorKind };
    use std::io::Result as IoResult;
    use std::ptr;
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    /// A trait for operations on mutable `[u8]`s.
    trait MutableByteVector {
        /// Sets all bytes of the receiver to the given value.
        fn set_memory(&mut self, value: u8);
    }

    impl MutableByteVector for Vec<u8> {
        #[inline]
        fn set_memory(&mut self, value: u8) {
            unsafe { ptr::write_bytes(self.as_mut_ptr(), value, self.len()) };
        }
    }

    #[cfg(test)]
    static mut TEST_EOF: bool = false;

    #[cfg(test)]
    static mut TEST_HAS_SEEN_EOF_BUFFER: bool = false;

    #[cfg(test)]
    static mut TEST_HAS_SEEN_REGULAR_BUFFER: bool = false;


    #[cfg(test)]
    fn get_reader() -> IoResult<File> {
        if unsafe { TEST_EOF } {
            unsafe { TEST_HAS_SEEN_EOF_BUFFER = true; }
            Ok(File::open("/dev/null").unwrap())
        } else {
            unsafe { TEST_HAS_SEEN_REGULAR_BUFFER = true; }
            Ok(File::open("tests/password").unwrap())
        }
    }

    #[cfg(not(test))]
    fn get_reader() -> IoResult<File> {
        File::open("/dev/tty")
    }

    pub fn read_password() -> IoResult<String> {
        let f = try!(get_reader());
        let fd = f.as_raw_fd();

        // Make two copies of the terminal settings. The first one will be modified
        // and the second one will act as a backup for when we want to set the
        // terminal back to its original state.
        let mut term = try!(termios::Termios::from_fd(fd));
        let term_orig = term;

        // Hide the password. This is what makes this function useful.
        term.c_lflag &= !termios::ECHO;

        // But don't hide the NL character when the user hits ENTER.
        term.c_lflag |= termios::ECHONL;

        // Save the settings for now.
        try!(termios::tcsetattr(fd, termios::TCSANOW, &term));

        // Read the password.
        let mut password = String::new();
        let mut reader = BufReader::new(f);
        match reader.read_line(&mut password) {
            Ok(_) => { },
            Err(err) => {
                // Reset the terminal and quit.
                try!(termios::tcsetattr(fd, termios::TCSANOW, &term_orig));

                // Return the original IoError.
                return Err(err);
            }
        };

        // Reset the terminal and quit.
        match termios::tcsetattr(fd, termios::TCSANOW, &term_orig) {
            Ok(_) => {},
            Err(err) => {
                unsafe { password.as_mut_vec() }.set_memory(0);
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
        let fd = get_reader().unwrap().as_raw_fd();
        let term_before = termios::Termios::from_fd(fd).unwrap();
        assert_eq!(read_password().unwrap(), "my-secret");
        let term_after = termios::Termios::from_fd(fd).unwrap();
        assert_eq!(term_before, term_after);
        unsafe { TEST_EOF = true; }
        assert!(!read_password().is_ok());
        let term_after = termios::Termios::from_fd(fd).unwrap();
        assert_eq!(term_before, term_after);
        assert!(unsafe { TEST_HAS_SEEN_REGULAR_BUFFER });
        assert!(unsafe { TEST_HAS_SEEN_EOF_BUFFER });
    }
}

#[cfg(windows)]
mod windows {
    extern crate winapi;
    extern crate kernel32;
    use std::io::{ Error, ErrorKind };
    use std::io::Result as IoResult;
    use std::ptr::null_mut;

    pub fn read_password() -> IoResult<String> {
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
pub use unix::read_password;
#[cfg(windows)]
pub use windows::read_password;

use std::io::{stderr, Write};

pub fn read_password_prompt<S>(prompt: S) -> IoResult<String>
    where S: Into<String> {
        // Print the prompt and then read the password.
        let mut serr = stderr();
        try!(serr.write(prompt.into().as_bytes()));
        try!(serr.flush());
        read_password()
    }
