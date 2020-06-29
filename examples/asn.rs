use std::env;

fn main() {
    let first_arg = env::args().nth(1).unwrap();
    let asn: cymrust::AsNumber = first_arg.parse().unwrap();

    let cymru = cymrust::cymru_asn(asn);
    println!("{:#?}", cymru)
}
