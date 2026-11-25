//! Certificate file content as written to a card (Figure 14): `CertificateLength (3 bytes, LSB first) ||
//! CertificateData || padding`.

use super::error::{PkiError, Result};

/// Build the file image. With `file_size` the image is zero padded to the file size.
pub fn build_image(cert_data: &[u8], file_size: Option<usize>) -> Result<Vec<u8>> {
    if cert_data.len() > 0xFF_FFFF {
        return Err(PkiError::Invalid("certificate data is too long".into()));
    }
    let mut img = Vec::with_capacity(cert_data.len() + 3);
    img.extend(&(cert_data.len() as u32).to_le_bytes()[..3]);
    img.extend(cert_data);
    if let Some(size) = file_size {
        if img.len() > size {
            return Err(PkiError::Invalid("certificate does not fit the file".into()));
        }
        img.resize(size, 0);
    }
    Ok(img)
}

/// The certificate (chain) bytes of a file image; padding is ignored.
pub fn parse_image(image: &[u8]) -> Result<&[u8]> {
    if image.len() < 3 {
        return Err(PkiError::Invalid("certificate file is shorter than its length field".into()));
    }
    let len = usize::from(image[0]) | usize::from(image[1]) << 8 | usize::from(image[2]) << 16;
    image
        .get(3..3 + len)
        .ok_or_else(|| PkiError::Invalid("certificate file is shorter than its CertificateLength".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_roundtrip() {
        let img = build_image(&[1, 2, 3], Some(10)).unwrap();
        assert_eq!(img, [3, 0, 0, 1, 2, 3, 0, 0, 0, 0]);
        assert_eq!(parse_image(&img).unwrap(), [1, 2, 3]);
        assert_eq!(build_image(&[9], None).unwrap(), [1, 0, 0, 9]);
        assert!(build_image(&[0; 8], Some(10)).is_err());
        assert!(parse_image(&[5, 0, 0, 1]).is_err());
        assert!(parse_image(&[1]).is_err());
        let big = build_image(&vec![7; 300], None).unwrap();
        assert_eq!(&big[..3], [0x2C, 0x01, 0]);
    }
}
