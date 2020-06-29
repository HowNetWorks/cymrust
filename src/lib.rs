//! Simple library to query [Team Cymru](https://www.team-cymru.org/)'s
//! [IP-to-ASN](https://www.team-cymru.org/IP-ASN-mapping.html) mapping
//! information via DNS.
//!
//! Please, see Team Cymru's documentation before using this library. Cymru also
//! warns not to use their mapping as Geo-IP service.
//!
//! For easiest IP-to-ASN mapping, see [`cymru_ip2asn`](fn.cymru_ip2asn.html)
//! function. To query only information about AS Number, see
//! [`cymru_asn`](fn.cymru_asn.html).

use std::cmp;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime};

use chrono::NaiveDate;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::Resolver;

/// `AsNumber` type to abstract away the fact that AS Number is (currently) 32
/// bit unsigned integer.
pub type AsNumber = u32;

/// IP-to-ASN mapping information
///
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct CymruIP2ASN {
    /// IP Address used in query
    pub ip_addr: IpAddr,
    /// BGP prefix
    pub bgp_prefix: String,
    /// BGP Origin's Autonomous System (AS) number
    pub as_number: AsNumber,
    /// Autonomous System (AS) description
    pub as_name: String,
    /// Country code
    pub country_code: String,
    /// Regional registrar name
    pub registry: String,
    /// BGP prefix allocation date
    pub allocated: Option<String>,
    /// When information contained in this struct expires
    pub expires: SystemTime,
}

/// ASN information
///
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct CymruASN {
    /// BGP Origin's Autonomous System (AS) number
    pub as_number: AsNumber,
    /// Country code
    pub country_code: String,
    /// Regional registrar name
    pub registry: String,
    /// BGP prefix allocation date
    pub allocated: Option<NaiveDate>,
    /// Autonomous System (AS) description
    pub as_name: String,
    /// When information contained in this struct expires
    pub expires: SystemTime,
}

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord)]
struct CymruOrigin {
    pub as_number: AsNumber,
    pub bgp_prefix: String,
    pub country_code: String,
    pub registry: String,
    pub allocated: Option<NaiveDate>,
    pub expires: SystemTime,
}

/// Query Cymru's IP-to-ASN mapping service using DNS
///
/// This function first queries [Cymru's
/// IP-to-ASN](https://www.team-cymru.org/IP-ASN-mapping.html) (AS number)
/// mapping to learn AS number(s) for IP. Then for every AS unique number, it
/// does a new query to get ASN information. The returned `CymruIP2ASN` is union
/// of IP-to-ASN mapping and ASN query information.
///
/// No caching is performed by this function.
///
/// # Errors
///
/// If DNS resolver fails or there's error in DNS query, the error is returned
/// as String
///
pub fn cymru_ip2asn(ip: IpAddr) -> Result<Vec<CymruIP2ASN>, Error> {
    let origins: Vec<CymruOrigin> = cymru_origin(ip)?;
    let mut results: Vec<CymruIP2ASN> = Vec::with_capacity(origins.len());

    'origins: for origin in origins {
        for result in &results {
            if origin.as_number == result.as_number {
                // Skip AS numbers we already know about
                continue 'origins;
            }
        }

        let asn: Vec<CymruASN> = cymru_asn(origin.as_number)?;

        let result = CymruIP2ASN {
            ip_addr: ip,
            bgp_prefix: origin.bgp_prefix,
            as_number: origin.as_number,
            as_name: asn[0].as_name.to_string(),
            country_code: origin.country_code,
            registry: origin.registry,
            allocated: origin.allocated.map(|s| s.to_string()),
            expires: cmp::min(origin.expires, asn[0].expires),
        };

        results.push(result);
    }

    if results.is_empty() {
        return Err(Error::NoResultsFound);
    }

    Ok(results)
}

/// Resolve information about AS number using DNS
///
/// This function queries [Cymru's
/// IP-to-ASN](https://www.team-cymru.org/IP-ASN-mapping.html) service and
/// returns information Cymru knows about given AS number.
///
/// No caching is performed by this function.
///
/// # Errors
///
/// If DNS resolver fails or there's error in DNS query, the error is returned
/// as String
///
pub fn cymru_asn<I: Into<AsNumber>>(asn: I) -> Result<Vec<CymruASN>, Error> {
    let query = format!("AS{}.asn.cymru.com.", asn.into());

    let (ttl, records) = resolve_txt(&query)?;
    let now = SystemTime::now();
    let cache_until: SystemTime = now + ttl;

    let results = parse_cymru_asn(records, cache_until);
    if results.is_empty() {
        return Err(Error::NoResultsFound);
    }
    Ok(results)
}

/// Resolve information about IP address
///
fn cymru_origin(ip: IpAddr) -> Result<Vec<CymruOrigin>, Error> {
    let query = match ip {
        IpAddr::V4(ipv4) => {
            let o = ipv4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(ipv6) => {
            let nibbles = ipv6_nibbles(ipv6);
            format!("{}.origin6.asn.cymru.com.", nibbles)
        }
    };

    let (ttl, records) = resolve_txt(&query)?;
    let now = SystemTime::now();
    let cache_until: SystemTime = now + ttl;

    let results = parse_cymru_origin(records, cache_until);
    if results.is_empty() {
        return Err(Error::NoResultsFound);
    }
    Ok(results)
}

/// Parse Cymru's ASN query result string into a struct
///
/// Sample DNS TXT response we try to parse:
///
///   "23028 | US | arin | 2002-01-04 | TEAM-CYMRU - Team Cymru Inc., US"
///
/// taken from https://www.team-cymru.org/IP-ASN-mapping.html#dns
///
fn parse_cymru_asn(records: Vec<String>, cache_until: SystemTime) -> Vec<CymruASN> {
    let mut results = Vec::with_capacity(records.len());

    for record in records {
        let fields: Vec<&str> = record.split('|').map(str::trim).collect();
        let as_number: AsNumber = match fields[0].parse() {
            Err(_) => continue,
            Ok(n) => n,
        };

        let result = CymruASN {
            as_number,
            country_code: fields[1].to_string(),
            registry: fields[2].to_string(),
            allocated: parse_date(fields[3]),
            as_name: fields[4].to_string(),
            expires: cache_until,
        };

        results.push(result);
    }

    results
}

/// Parse Cymru's Origin query result string into a structs
///
/// Sample DNS TXT response we try to parse:
///
///   "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
///
/// taken from https://www.team-cymru.org/IP-ASN-mapping.html#dns
///
fn parse_cymru_origin(records: Vec<String>, cache_until: SystemTime) -> Vec<CymruOrigin> {
    let mut results = Vec::with_capacity(records.len());

    for record in records {
        let fields: Vec<&str> = record.split('|').map(str::trim).collect();

        let as_numbers: Vec<&str> = fields[0].split(' ').map(str::trim).collect();

        for asn in as_numbers {
            let as_number: AsNumber = match asn.parse() {
                Err(_) => continue,
                Ok(n) => n,
            };

            let result = CymruOrigin {
                as_number,
                bgp_prefix: fields[1].to_string(),
                country_code: fields[2].to_string(),
                registry: fields[3].to_string(),
                allocated: parse_date(fields[4]),
                expires: cache_until,
            };
            results.push(result);
        }
    }

    results
}

/// Resolve TXT record
///
/// This is used to talk with Cymru. We expect them to provide us with ASCII
/// strings which is safe to decode into UTF-8 Strings. TXT records which are
/// not valid UTF-8 are silently discarded.
///
fn resolve_txt(name: &str) -> Result<(Duration, Vec<String>), Error> {
    let mut txts: Vec<String> = Vec::new();
    let resolver = Resolver::from_system_conf()?;
    let response = resolver.txt_lookup(name)?;
    let valid_until = response.valid_until();
    let ttl = valid_until - Instant::now();

    for record in response.iter() {
        for data in record.txt_data() {
            if let Ok(txt) = std::str::from_utf8(data) {
                txts.push(txt.to_owned());
            }
        }
    }

    Ok((ttl, txts))
}

/// Convert IPv6 address into nibble format string
///
fn ipv6_nibbles(ip: Ipv6Addr) -> String {
    fn u8_to_str(i: u8) -> String {
        std::char::from_digit(u32::from(i), 16).unwrap().to_string()
    }
    let mut result: Vec<String> = Vec::new();
    for o in ip.octets().iter().rev() {
        result.push(u8_to_str(o & 0x0F));
        result.push(u8_to_str(o >> 4));
    }
    result.join(".")
}

/// Parse date in YYYY-MM-DD format ignoring timezones
///
fn parse_date(date: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()
}

#[derive(Debug)]
pub enum Error {
    /// Query found no results
    NoResultsFound,

    /// I/O error
    Io(io::Error),

    /// DNS Resolver error
    Resolver(ResolveError),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::NoResultsFound => None,
            Error::Io(err) => Some(err),
            Error::Resolver(err) => Some(err),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoResultsFound => write!(f, "Query found no results"),
            Error::Io(err) => err.fmt(f),
            Error::Resolver(err) => err.fmt(f),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<ResolveError> for Error {
    fn from(err: ResolveError) -> Self {
        Error::Resolver(err)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    #[test]
    fn test_ipv6_nibbles() {
        use super::ipv6_nibbles;
        assert_eq!(
            ipv6_nibbles("2001:db8:0123:4567:89ab:cdef:0123:4567".parse().unwrap()),
            "7.6.5.4.3.2.1.0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.8.b.d.0.1.0.0.2"
        );
    }

    #[test]
    fn test_parse_cymru_asn() {
        use super::{parse_cymru_asn, parse_date, CymruASN};
        let vec = vec!["23028 | US | arin | 2002-01-04 | TEAMCYMRU - SAUNET".to_string()];
        let ttl = SystemTime::now();
        let results: Vec<CymruASN> = parse_cymru_asn(vec, ttl);
        assert_eq!(results.len(), 1);
        let first = results.first().unwrap();
        assert_eq!(first.as_number, 23028);
        assert_eq!(first.country_code, "US");
        assert_eq!(first.registry, "arin");
        assert_eq!(first.allocated, parse_date("2002-01-04"));
        assert_eq!(first.as_name, "TEAMCYMRU - SAUNET");
    }

    #[test]
    fn test_parse_cymru_asn_empty() {
        use super::{parse_cymru_asn, CymruASN};
        let ttl = SystemTime::now();
        let results: Vec<CymruASN> = parse_cymru_asn(vec!["".to_string()], ttl);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_parse_cymru_origin() {
        use super::{parse_cymru_origin, parse_date, CymruOrigin};
        let vec = vec!["23028 | 216.90.108.0/24 | US | arin | 1998-09-25".to_string()];
        let ttl = SystemTime::now();
        let results: Vec<CymruOrigin> = parse_cymru_origin(vec, ttl);
        assert_eq!(results.len(), 1);
        let first = results.first().unwrap();
        assert_eq!(first.as_number, 23028);
        assert_eq!(first.bgp_prefix, "216.90.108.0/24");
        assert_eq!(first.country_code, "US");
        assert_eq!(first.registry, "arin");
        assert_eq!(first.allocated, parse_date("1998-09-25"));
    }

    #[test]
    fn test_parse_cymru_origin_empty() {
        use super::{parse_cymru_origin, CymruOrigin};
        let ttl = SystemTime::now();
        let results: Vec<CymruOrigin> = parse_cymru_origin(vec!["".to_string()], ttl);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_parse_cymru_origin_multiple_asn() {
        use super::{parse_cymru_origin, parse_date, CymruOrigin};
        let vec = vec!["1 23 456 7890 | 203.0.113.0/24 | GB | ripencc | 2006-02-17".to_string()];
        let ttl = SystemTime::now();
        let results: Vec<CymruOrigin> = parse_cymru_origin(vec, ttl);
        assert_eq!(results.len(), 4);
        let asns = [1, 23, 456, 7890];
        for item in 0..3 {
            assert_eq!(results[item].as_number, asns[item]);
            assert_eq!(results[item].bgp_prefix, "203.0.113.0/24");
            assert_eq!(results[item].country_code, "GB");
            assert_eq!(results[item].registry, "ripencc");
            assert_eq!(results[item].allocated, parse_date("2006-02-17"));
        }
    }
}
