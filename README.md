# Rustastic Password

[![Build status](https://travis-ci.org/conradkleinespel/rustastic-password.svg?branch=master)](https://travis-ci.org/conradkleinespel/rustastic-password)
[![Build status](https://ci.appveyor.com/api/projects/status/812odw3tw6oec5sw/branch/master?svg=true)](https://ci.appveyor.com/project/conradkleinespel/rustastic-password/branch/master)

This [Rust](http://www.rust-lang.org/) package allows you to safely read
passwords from standard input in a console application.

You can build the documentation with `cargo doc` or [view it online](https://conradk.com/docs/rustastic-password/).

The source code is released under the MIT license.

I'd appreciate feedback if you use this library :-)

## Usage

Add `rpassword` as a dependency in Cargo.toml:

```toml
[dependencies]
rpassword = "0.3"
```

Import the `rpassword` crate and use the `read_password()`
or `read_password_prompt()` function:

```rust
extern crate rpassword;

use rpassword::read_password;

fn main() {
    let password = read_password_prompt("Type a password: ").unwrap();
    println!("The password is: '{}'", password);
}
```

## Contributors

* [@BartMassey](https://github.com/BartMassey)
* [@conradkleinespel](https://github.com/conradkleinespel)
* [@dcuddeback](https://github.com/dcuddeback)
* [@equalsraf](https://github.com/equalsraf)
* [@JanLikar](https://github.com/JanLikar)
* [@petevine](https://github.com/petevine)
* [@psych0d0g](https://github.com/psych0d0g)
* [@retep998](https://github.com/retep998)
