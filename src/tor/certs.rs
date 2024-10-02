use std::fmt::Error;

#[allow(dead_code)]
struct RawCert {
    cert_type: u8,
    cert_len: u16,
    certificate: Vec<u8>,
}

impl RawCert {
    fn new(cert_type: u8, cert_len: u16, certificate: Vec<u8>) -> Self {
        Self {
            cert_type,
            cert_len,
            certificate,
        }
    }

    #[allow(dead_code)]
    fn get_from_bytes(bytes: &Vec<u8>) -> Result<Vec<Self>, Error> {
        let numbers_of_certs = bytes.get(0).unwrap().to_owned();
        let mut certs = Vec::new();
        let mut i = 1u32;
        let mut certs_num = 0u8;
        while i < bytes.len() as u32 && certs_num < numbers_of_certs {
            let cert_type = bytes.get(i as usize).unwrap().to_owned();
            i += 1;

            let cert_len = {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&bytes.get(i as usize..i as usize + 2).unwrap());
                u16::from_be_bytes(buf)
            };
            i += 2;

            let certificate = {
                let mut buf = vec![0u8; cert_len as usize];
                buf.copy_from_slice(&bytes.get(i as usize..i as usize + cert_len as usize).unwrap());
                buf
            };
            i += cert_len as u32;
            certs_num += 1;

            certs.push(Self::new(cert_type, cert_len, certificate));
        }

        Ok(certs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_cert_new() {
        let cert_type = 1;
        let cert_len = 3;
        let certificate = vec![1, 2, 3];
        let cert = RawCert::new(cert_type, cert_len, certificate.clone());
        assert_eq!(cert.cert_type, cert_type);
        assert_eq!(cert.cert_len, cert_len);
        assert_eq!(cert.certificate, certificate);
    }

    #[test]
    fn test_get_from_bytes_single_cert() {
        let bytes = vec![1, 1, 0, 3, 1, 2, 3];
        let certs = RawCert::get_from_bytes(&bytes).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].cert_type, 1u8);
        assert_eq!(certs[0].cert_len, 3u16);
        assert_eq!(certs[0].certificate, vec![1u8, 2u8, 3u8]);
    }

    #[test]
    fn test_get_from_bytes_multiple_certs() {
        let bytes = vec![2, 1, 0, 3, 1, 2, 3, 2, 0, 2, 4, 5];
        let certs = RawCert::get_from_bytes(&bytes).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].cert_type, 1);
        assert_eq!(certs[0].cert_len, 3);
        assert_eq!(certs[0].certificate, vec![1, 2, 3]);
        assert_eq!(certs[1].cert_type, 2);
        assert_eq!(certs[1].cert_len, 2);
        assert_eq!(certs[1].certificate, vec![4, 5]);
    }

    #[test]
    #[should_panic]
    fn test_get_from_bytes_invalid_length() {
        let bytes = vec![1, 1, 0, 3, 1, 2]; // Incomplete certificate data
        RawCert::get_from_bytes(&bytes).unwrap();
    }
}
