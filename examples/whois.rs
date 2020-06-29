use std::env;
use std::net::IpAddr;

fn main() {
    let first_arg = env::args().nth(1).unwrap();
    let ip: IpAddr = first_arg.parse().unwrap();

    let cymru = cymrust::cymru_ip2asn(ip);
    println!("{:#?}", cymru)
}
