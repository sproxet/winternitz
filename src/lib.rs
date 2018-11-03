pub mod util {
    use std::error::Error;
    use std::str;

    /// Format a string of bytes into a hex string.
    ///
    /// ```
    /// assert_eq!(winternitz::util::format_bytes(&[0x48, 0x69, 0x2e]), "0x48692e");
    /// ```
    pub fn format_bytes(bytes: &[u8]) -> String {
        let mut s = String::from("0x");
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// Change a formatted bytestring into a string of bytes.
    ///
    /// ```
    /// assert_eq!(winternitz::util::deformat_bytes("0x48692e").unwrap(), vec![0x48, 0x69, 0x2e]);
    /// assert_eq!(winternitz::util::deformat_bytes("123456").unwrap(), vec![0x12, 0x34, 0x56]);
    /// assert!(winternitz::util::deformat_bytes("invalid").is_err());
    /// ```
    pub fn deformat_bytes(bytestr: &str) -> Result<Vec<u8>, Box<Error>> {
        let mut out = Vec::new();

        if bytestr.len() < 2 || bytestr.len() % 2 != 0 {
            return Err(From::from("invalid bytestr length"));
        }

        let bs = match &bytestr[0..2] {
            "0x" => {
                if bytestr.len() < 4 {
                    return Err(From::from("invalid bytestr"));
                }
                &bytestr[2..]
            },
            _ => bytestr,
        };

        for c in bs.as_bytes().chunks(2) {
            let v = str::from_utf8(c)?;
            out.push( u8::from_str_radix(v, 16)? );
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
}
