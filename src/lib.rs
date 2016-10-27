extern crate chrono;
extern crate resolve;

use std::io;
use std::net::{IpAddr, Ipv6Addr};

use chrono::NaiveDate;

use resolve::config::default_config;
use resolve::record::Txt;
use resolve::resolver::DnsResolver;


/// IP-to-ASN mapping information
///
#[derive(Debug, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct CymruIP2ASN {
    /// IP Address used in query
    pub ip_addr: IpAddr,
    /// BGP prefix
    pub bgp_prefix: String,
    /// BGP Origin's Autonomous System (AS) number
    pub as_number: u32,
    /// Autonomous System (AS) description
    pub as_name: String,
    /// Country code
    pub country_code: String,
    /// Regional registrar name
    pub registry: String,
    /// BGP prefix alllocation date
    pub allocated: Option<NaiveDate>,
}

#[derive(Debug, Hash, PartialEq, PartialOrd, Eq, Ord)]
struct CymruASN {
    pub as_number: u32,
    pub country_code: String,
    pub registry: String,
    pub allocated: Option<NaiveDate>,
    pub as_name: String,
}

#[derive(Debug, Hash, PartialEq, PartialOrd, Eq, Ord)]
struct CymruOrigin {
    pub as_number: u32,
    pub bgp_prefix: String,
    pub country_code: String,
    pub registry: String,
    pub allocated: Option<NaiveDate>,
}


/// Query Cymru's IP-to-ASN mapping service
///
/// This function produces two DNS queries over network.
///
pub fn cymru_ip2asn(ip: IpAddr) -> Result<CymruIP2ASN, String> {
    let origin: CymruOrigin = try!(cymru_origin(ip));
    let asn: CymruASN = try!(cymru_asn(origin.as_number));
    let result = CymruIP2ASN {
        ip_addr: ip,
        bgp_prefix: origin.bgp_prefix,
        as_number: origin.as_number,
        as_name: asn.as_name,
        country_code: origin.country_code,
        registry: origin.registry,
        allocated: origin.allocated,
    };
    Ok(result)
}


/// Resolve information about AS number
///
fn cymru_asn(asn: u32) -> Result<CymruASN, String> {
    let query = format!("AS{}.asn.cymru.com", asn.to_string());

    match resolve_txt(&query) {
        Err(err) => Err(err.to_string()),
        Ok(records) => parse_cymru_asn(records),
    }
}


/// Resolve information about IP address
///
fn cymru_origin(ip: IpAddr) -> Result<CymruOrigin, String> {
    let query = match ip {
        IpAddr::V4(ipv4) => {
            let o = ipv4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(ipv6) => {
            let nibbles = ipv6_nibbles(ipv6);
            format!("{}.origin6.asn.cymru.com", nibbles)
        }
    };

    match resolve_txt(&query) {
        Err(err) => Err(err.to_string()),
        Ok(records) => parse_cymru_origin(records),
    }
}


/// Parse Cymru's ASN query result string into a struct
///
/// Sample DNS TXT response we try to parse:
///
///   "23028 | US | arin | 2002-01-04 | TEAM-CYMRU - Team Cymru Inc., US"
///
/// taken from https://www.team-cymru.org/IP-ASN-mapping.html#dns
///
fn parse_cymru_asn(records: Vec<String>) -> Result<CymruASN, String> {
    if records.len() != 1 {
        return Err("Invalid number of records found".to_string());
    }

    let fields: Vec<&str> = records[0].split("|").map(str::trim).collect();
    let as_number: u32 = try!(fields[0].parse().map_err(|_| "u32 parse error"));

    let result = CymruASN {
        as_number: as_number,
        country_code: fields[1].to_string(),
        registry: fields[2].to_string(),
        allocated: parse_date(fields[3]),
        as_name: fields[4].to_string(),
    };

    Ok(result)
}


/// Parse Cymru's Origin query result string into a struct
///
/// Sample DNS TXT response we try to parse:
///
///   "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
///
/// taken from https://www.team-cymru.org/IP-ASN-mapping.html#dns
///
fn parse_cymru_origin(records: Vec<String>) -> Result<CymruOrigin, String> {
    if records.len() != 1 {
        return Err("Invalid number of TXT records found".to_string());
    }

    let fields: Vec<&str> = records[0].split("|").map(str::trim).collect();
    let as_number: u32 = try!(fields[0].parse().map_err(|_| "u32 parse error"));

    let result = CymruOrigin {
        as_number: as_number,
        bgp_prefix: fields[1].to_string(),
        country_code: fields[2].to_string(),
        registry: fields[3].to_string(),
        allocated: parse_date(fields[4]),
    };

    Ok(result)
}


/// Resolve TXT record
///
/// This is used to talk with Cymru. We expect them to provide us with ASCII strings which is safe
/// to decode into UTF-8 Strings. TXT records which are not valid UTF-8 are silently discarded.
///
fn resolve_txt(name: &str) -> io::Result<Vec<String>> {
    let r = try!(DnsResolver::new(try!(default_config())));
    let recs: Vec<Txt> = try!(r.resolve_record(name));
    let mut txts = Vec::with_capacity(recs.len());

    for rec in recs.into_iter() {
        let as_str = String::from_utf8(rec.data);
        if as_str.is_ok() {
            txts.push(as_str.unwrap());
        }
    }
    Ok(txts)
}


/// Convert IPv6 address into nibble format string
///
fn ipv6_nibbles(ip: Ipv6Addr) -> String {
    let o = ip.octets();
    format!("{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.\
             {:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}",
             o[15] & 0x0f, o[15] >> 4, o[14] & 0x0f, o[14] >> 4,
             o[13] & 0x0f, o[13] >> 4, o[12] & 0x0f, o[12] >> 4,
             o[11] & 0x0f, o[11] >> 4, o[10] & 0x0f, o[10] >> 4,
             o[9] & 0x0f,  o[9] >> 4,  o[8] & 0x0f,  o[8] >> 4,
             o[7] & 0x0f,  o[7] >> 4,  o[6] & 0x0f,  o[6] >> 4,
             o[5] & 0x0f,  o[5] >> 4,  o[4] & 0x0f,  o[4] >> 4,
             o[3] & 0x0f,  o[3] >> 4,  o[2] & 0x0f,  o[2] >> 4,
             o[1] & 0x0f,  o[1] >> 4,  o[0] & 0x0f,  o[0] >> 4,
    )
}


/// Parse date in YYYY-MM-DD format ignoring timezones
///
fn parse_date(date: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_ipv6_nibbles() {
        use super::ipv6_nibbles;
        assert_eq!(ipv6_nibbles("2001:db8:0123:4567:89ab:cdef:0123:4567".parse().unwrap()),
                   "7.6.5.4.3.2.1.0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.8.b.d.0.1.0.0.2");
    }

    #[test]
    fn test_parse_cymru_asn() {
        use super::{CymruASN, parse_cymru_asn, parse_date};
        let vec = vec!["23028 | US | arin | 2002-01-04 | TEAMCYMRU - SAUNET".to_string()];
        let parsed: CymruASN = parse_cymru_asn(vec).unwrap();
        let valid = CymruASN {
            as_number: 23028,
            country_code: "US".to_string(),
            registry: "arin".to_string(),
            allocated: parse_date("2002-01-04"),
            as_name: "TEAMCYMRU - SAUNET".to_string(),
        };
        assert_eq!(parsed, valid)
    }

    #[test]
    fn test_parse_cymru_origin() {
        use super::{CymruOrigin, parse_cymru_origin, parse_date};
        let vec = vec!["23028 | 216.90.108.0/24 | US | arin | 1998-09-25".to_string()];
        let parsed: CymruOrigin = parse_cymru_origin(vec).unwrap();
        assert_eq!(parsed.as_number, 23028);
        assert_eq!(parsed.bgp_prefix, "216.90.108.0/24");
        assert_eq!(parsed.country_code, "US");
        assert_eq!(parsed.registry, "arin");
        assert_eq!(parsed.allocated, parse_date("1998-09-25"));
    }

}
