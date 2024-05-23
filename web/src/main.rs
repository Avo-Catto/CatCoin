mod backend;
use backend::Wallet;

/*
fn main() {
    let mnemonics = vec![
        "Avocados".to_string(),
        "sind".to_string(),
        "nicht".to_string(),
        "lecker!".to_string(),
    ];
    let mut my_wallet = Wallet::new(mnemonics, "aaah").expect("DEBUG - construct new wallet error");

    let addr = my_wallet.gen_address(0);
    println!("DEBUG - idx: {} - {}", 0, addr); // DEBUG

    let _ = my_wallet.save_keys();
}
*/

#[macro_use]
extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    "Hello world!"
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index])
}

// TODO: credits hugo
