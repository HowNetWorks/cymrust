# cymrust [![Crates.io](https://img.shields.io/crates/v/cymrust.svg)](https://crates.io/crates/cymrust) [![docs.rs](https://docs.rs/cymrust/badge.svg)](https://docs.rs/cymrust/) [![CircleCI](https://circleci.com/gh/HowNetWorks/cymrust.svg?style=shield)](https://circleci.com/gh/HowNetWorks/cymrust)

Simple library to query [Team Cymru](https://www.team-cymru.org/)'s
[IP-to-ASN](https://www.team-cymru.org/IP-ASN-mapping.html) mapping information
via DNS.

Please, see Team Cymru's documentation before using this library.

Cymrust's docs can be found from [docs.rs](https://docs.rs/cymrust/).

# Example

```rust
use std::env;
use std::net::IpAddr;

fn main() {
    let first_arg = env::args().nth(1).unwrap();
    let ip: IpAddr = first_arg.parse().unwrap();

    let cymru = cymrust::cymru_ip2asn(ip);
    println!("{:#?}", cymru)
}
```

```console
$ cargo run -q --example whois 8.8.8.8
Ok(
    [
        CymruIP2ASN {
            ip_addr: V4(
                8.8.8.8
            ),
            bgp_prefix: "8.8.8.0/24",
            as_number: 15169,
            as_name: "GOOGLE - Google Inc., US",
            country_code: "US",
            registry: "arin",
            allocated: None,
            expires: SystemTime {
                tv_sec: 1483648521,
                tv_nsec: 906456000
            }
        }
    ]
)
```
