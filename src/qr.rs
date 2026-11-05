//! Reading two-step-verification QR codes from the screen.
//!
//! Sites show the TOTP secret as a QR code holding an `otpauth://` link.
//! Instead of making the user find and copy the hidden text key, VaultRust
//! takes one screenshot (kept in memory only and wiped afterwards), looks for
//! QR codes in it and returns the first `otpauth://` link it finds.

use zeroize::{Zeroize, Zeroizing};

/// Why no code was found.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    #[error("couldn't take a screenshot")]
    Capture,
    #[error("no QR code found on screen — make sure the whole code is visible, then try again")]
    NoCode,
    #[error("found a QR code, but it isn't a two-step verification code")]
    NotOtp,
}

/// Find an `otpauth://` link in a greyscale image (`w` × `h`, one byte per
/// pixel, rows top to bottom).
pub fn find_otpauth(gray: &[u8], w: usize, h: usize) -> Result<Zeroizing<String>, ScanError> {
    if w == 0 || h == 0 || gray.len() < w * h {
        return Err(ScanError::NoCode);
    }
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| gray[y * w + x]);
    let mut saw_code = false;
    for grid in img.detect_grids() {
        if let Ok((_, content)) = grid.decode() {
            let content = Zeroizing::new(content);
            saw_code = true;
            if content
                .trim_start()
                .get(..10)
                .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
            {
                return Ok(Zeroizing::new(content.trim().to_string()));
            }
        }
    }
    Err(if saw_code {
        ScanError::NotOtp
    } else {
        ScanError::NoCode
    })
}

/// Screenshot every monitor and look for a two-step verification QR code.
/// VaultRust's own window is left out of the screenshot while screen-capture
/// protection is on, so a code behind it is still found.
pub fn scan_screen() -> Result<Zeroizing<String>, ScanError> {
    let (mut gray, w, h) = crate::os_protect::capture_screen_gray().ok_or(ScanError::Capture)?;
    let found = find_otpauth(&gray, w, h);
    gray.zeroize();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Draw `text` as a QR code at `scale` pixels per module at (`ox`, `oy`)
    /// inside a larger white image.
    fn render(text: &str, scale: usize, ox: usize, oy: usize, w: usize, h: usize) -> Vec<u8> {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let n = code.width();
        let colors = code.to_colors();
        let mut img = vec![255u8; w * h];
        for my in 0..n {
            for mx in 0..n {
                if colors[my * n + mx] == qrcode::Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            img[(oy + my * scale + dy) * w + ox + mx * scale + dx] = 0;
                        }
                    }
                }
            }
        }
        img
    }

    #[test]
    fn finds_an_otpauth_code_anywhere_in_a_large_image() {
        let uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let (w, h) = (1600, 900);
        let img = render(uri, 4, 1100, 500, w, h);
        assert_eq!(find_otpauth(&img, w, h).unwrap().as_str(), uri);
    }

    #[test]
    fn other_qr_codes_and_blank_screens_are_reported() {
        let (w, h) = (400, 400);
        let img = render("https://example.com", 4, 40, 40, w, h);
        assert_eq!(find_otpauth(&img, w, h).unwrap_err(), ScanError::NotOtp);
        assert_eq!(
            find_otpauth(&vec![255; w * h], w, h).unwrap_err(),
            ScanError::NoCode
        );
        assert_eq!(find_otpauth(&[], 0, 0).unwrap_err(), ScanError::NoCode);
    }
}

#[cfg(all(test, windows))]
mod screen_tests {
    /// Takes a real screenshot (kept in memory) and scans it.
    #[test]
    #[ignore = "reads the real screen"]
    fn real_screen_capture_and_scan() {
        let t = std::time::Instant::now();
        let (gray, w, h) = crate::os_protect::capture_screen_gray().expect("screenshot");
        let captured = t.elapsed();
        let result = super::find_otpauth(&gray, w, h);
        eprintln!(
            "screen {w}x{h}: capture {captured:?}, scan {:?}, result {:?}",
            t.elapsed() - captured,
            result.as_ref().map(|_| "found").map_err(|e| e.clone())
        );
        assert!(w > 0 && h > 0 && gray.iter().any(|&p| p != gray[0]));
    }
}
