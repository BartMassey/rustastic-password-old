extern crate rpassword;

fn main() {
    match rpassword::read_password_prompt("Password: ") {
        Ok(pass) => println!("Your password is {}", pass),
        Err(e) => panic!("password read: {}", e)
    }
}
