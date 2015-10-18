extern crate keepass;
extern crate rpassword;

use std::fs::File;
use std::env;
use std::collections::HashMap;
use std::process;
use std::io::{Read, Write, stdout};
use rpassword::read_password;


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("{}: missing filename", args[0]);
        process::exit(1);
    }

    let filename = &args[1];
    let mut f = File::open(filename).unwrap();

    print!("Database password: ");
    stdout().flush().unwrap();
    let password = read_password().unwrap();
    let key = keepass::kdb3::transform_password(password.as_ref());


    let mut header_data: [u8; 124] = [0; 124];
    f.read(&mut header_data).unwrap();

    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    let mut body_data = &mut buffer[..];

    let db = keepass::kdb3::import(&key, &header_data, &mut body_data).unwrap();

    print_query(db);
}


fn print_query(db: keepass::kdb3::format::Database) {
    let mut groups = HashMap::new();
    let mut glen = 1;

    for g in db.groups {
        if g.title.len() > glen {
            glen = g.title.len();
        }
        groups.insert(g.id, g.title);
    }

    for e in db.entries {
        let def = "?".to_string();
        print!("{:.*}", glen, match groups.get(&e.group_id) {
            Some(g) => g,
            None    => &def,
        });
        println!("\t| {}\t| {}\t| {}\t| {}", e.title, e.username, e.password, e.url);
    }
}
