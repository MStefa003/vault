//! Card and address details for filling in web forms (checkout, shipping,
//! sign-up) from credit card and identity items.
//!
//! Items keep these details in free-form fields, so the values are found by
//! the field names VaultRust writes (in any interface language) and, for
//! items imported or edited by hand, by words in the field name. Identities
//! made before VaultRust had separate city / postal code / country fields
//! have the whole address in one multi-line field; [`split_address`] takes
//! it apart.

use zeroize::Zeroizing;

use crate::model::{Entry, EntryKind};

/// The value of the first non-empty field named `labels[i]` (as VaultRust
/// writes it, in any language), or else whose name contains one of `hints`.
fn field<'a>(e: &'a Entry, labels: &[&str], hints: &[&str]) -> Option<&'a str> {
    let filled = || e.fields.iter().filter(|f| !f.value.trim().is_empty());
    filled()
        .find(|f| labels.iter().any(|l| crate::i18n::is_any(&f.label, l)))
        .or_else(|| {
            filled().find(|f| {
                let l = f.label.to_lowercase();
                hints.iter().any(|h| l.contains(h))
            })
        })
        .map(|f| f.value.trim())
}

/// The card network, from the number's first digits (lower-case, as
/// payment forms name them; empty if unknown).
pub fn card_brand(digits: &str) -> &'static str {
    let n = |len: usize| digits.get(..len).and_then(|p| p.parse::<u32>().ok());
    match (n(1), n(2), n(3), n(4), n(6)) {
        (Some(4), ..) => "visa",
        (_, Some(34 | 37), ..) => "amex",
        (_, Some(51..=55), ..) | (.., Some(2221..=2720), _) => "mastercard",
        (.., Some(6011), _) | (_, Some(65), ..) | (_, _, Some(644..=649), ..) => "discover",
        (_, Some(36 | 38 | 39), ..) | (_, _, Some(300..=305), ..) => "diners",
        (.., Some(3528..=3589), _) => "jcb",
        (_, Some(62), ..) => "unionpay",
        (_, Some(50 | 56..=58 | 63 | 67), ..) => "maestro",
        _ => "",
    }
}

/// The brand's name as printed on cards.
pub fn brand_name(brand: &str) -> &'static str {
    match brand {
        "visa" => "Visa",
        "amex" => "American Express",
        "mastercard" => "Mastercard",
        "discover" => "Discover",
        "diners" => "Diners Club",
        "jcb" => "JCB",
        "unionpay" => "UnionPay",
        "maestro" => "Maestro",
        _ => "",
    }
}

/// What a payment form needs from a card item.
pub struct Card<'a> {
    pub name: &'a str,
    /// Digits only.
    pub number: Zeroizing<String>,
    /// "01"–"12", or empty.
    pub month: String,
    /// Four digits, or empty.
    pub year: String,
    pub code: &'a str,
    pub brand: &'static str,
}

pub fn card(e: &Entry) -> Option<Card<'_>> {
    if e.kind != EntryKind::CreditCard {
        return None;
    }
    let number: Zeroizing<String> = Zeroizing::new(
        field(e, &["Card number"], &["card number", "number", "αριθμ"])
            .unwrap_or("")
            .chars()
            .filter(char::is_ascii_digit)
            .collect(),
    );
    let (month, year) = e
        .card_expiry_month()
        .map(|(m, y)| (format!("{m:02}"), y.to_string()))
        .unwrap_or_default();
    Some(Card {
        name: field(e, &["Cardholder name"], &["holder", "name on", "κάτοχ"]).unwrap_or(""),
        brand: card_brand(&number),
        number,
        month,
        year,
        code: field(
            e,
            &["Security code (CVV)"],
            &["cvv", "cvc", "csc", "security code", "κωδικός ασφαλείας"],
        )
        .unwrap_or(""),
    })
}

/// A card for lists: "Visa •••• 4242 · 08/27" (no secrets beyond the last
/// four digits, which cards print and receipts show).
pub fn card_summary(e: &Entry) -> String {
    let Some(c) = card(e) else {
        return String::new();
    };
    let mut parts = Vec::new();
    let brand = brand_name(c.brand);
    if c.number.len() >= 4 {
        let last = &c.number[c.number.len() - 4..];
        parts.push(if brand.is_empty() {
            format!("•••• {last}")
        } else {
            format!("{brand} •••• {last}")
        });
    }
    if !c.month.is_empty() {
        parts.push(format!("{}/{}", c.month, &c.year[2..]));
    }
    parts.join(" · ")
}

/// What an address or contact form needs from an identity item.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub given: String,
    pub middle: String,
    pub family: String,
    pub email: String,
    pub phone: String,
    /// The street lines.
    pub street: Vec<String>,
    pub city: String,
    pub region: String,
    pub postcode: String,
    pub country: String,
}

const HONORIFICS: [&str; 9] = [
    "mr", "mrs", "ms", "miss", "mx", "dr", "prof", "sir", "madam",
];

/// "Dr Jane Q. Public" -> ("Jane", "Q.", "Public").
pub fn split_name(full: &str) -> (String, String, String) {
    let mut words: Vec<&str> = full.split_whitespace().collect();
    while words.len() > 1
        && HONORIFICS.contains(&words[0].trim_end_matches('.').to_lowercase().as_str())
    {
        words.remove(0);
    }
    match words.as_slice() {
        [] => Default::default(),
        [only] => (only.to_string(), String::new(), String::new()),
        [first, middle @ .., last] => (first.to_string(), middle.join(" "), last.to_string()),
    }
}

/// Lines of a one-field address, taken apart.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Address {
    pub street: Vec<String>,
    pub city: String,
    pub region: String,
    pub postcode: String,
    pub country: String,
}

fn has_digit(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_digit())
}

/// A word that may be (part of) a postal code: digits, or letters and
/// digits mixed ("SW1A", "1AA", "62701-1234"), at most 10 characters.
fn postcode_word(w: &str) -> bool {
    (2..=10).contains(&w.len())
        && has_digit(w)
        && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// A city line with its postal code: "105 63 Athens", "1012 AB Amsterdam",
/// "Springfield, IL 62701", "London SW1A 2AA". Returns (city, region,
/// postcode).
fn city_line(line: &str) -> Option<(String, String, String)> {
    let words: Vec<&str> = line.split_whitespace().collect();
    if words.is_empty() || !has_digit(line) {
        return None;
    }
    // The code first (most of Europe).
    if words[0].starts_with(|c: char| c.is_ascii_digit()) && postcode_word(words[0]) {
        let mut code = vec![words[0]];
        // "105 63" (Greece, Sweden…), "1012 AB" (Netherlands).
        if let Some(next) = words.get(1).filter(|_| words.len() > 2) {
            let digits = next.len() <= 3 && next.chars().all(|c| c.is_ascii_digit());
            let letters = next.len() == 2 && next.chars().all(|c| c.is_ascii_uppercase());
            if digits || letters {
                code.push(next);
            }
        }
        let city = words[code.len()..].join(" ");
        return (!city.is_empty() && !has_digit(&city)).then(|| {
            (
                city.trim_matches(',').to_string(),
                String::new(),
                code.join(" "),
            )
        });
    }
    // The code last (US, UK, Canada…).
    let mut n = 1;
    let last = *words.last()?;
    if !postcode_word(last) {
        return None;
    }
    // "SW1A 2AA", "K1A 0B1": two parts of letters and digits.
    if words.len() >= 3 {
        let before = words[words.len() - 2];
        if postcode_word(before)
            && before.chars().any(|c| c.is_ascii_alphabetic())
            && last.len() == 3
        {
            n = 2;
        }
    }
    // A short number at the end is a house number ("Main Street 12").
    if n == 1 && last.len() < 4 {
        return None;
    }
    let code = words[words.len() - n..].join(" ");
    let rest = words[..words.len() - n].join(" ");
    let rest = rest.trim().trim_end_matches(',');
    if rest.is_empty() || has_digit(rest) {
        return None;
    }
    // "Springfield, IL" or "Springfield IL".
    let (city, region) = match rest.rsplit_once(',') {
        Some((c, r)) => (c.trim(), r.trim()),
        None => match rest.rsplit_once(' ') {
            Some((c, r)) if r.len() == 2 && r.chars().all(|c| c.is_ascii_uppercase()) => (c, r),
            _ => (rest, ""),
        },
    };
    Some((city.to_string(), region.to_string(), code))
}

/// Take apart an address written on several lines.
pub fn split_address(text: &str) -> Address {
    let mut lines: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let mut a = Address::default();
    if lines.len() < 2 {
        a.street = lines;
        return a;
    }
    // A postal code on a line of its own: older imports wrote street, city,
    // state, postal code and country on separate lines.
    if let Some(i) = lines
        .iter()
        .rposition(|l| l.split_whitespace().count() <= 2 && l.split_whitespace().all(postcode_word))
        .filter(|&i| i >= 2)
    {
        a.postcode = lines[i].clone();
        a.country = lines.get(i + 1..).map(|r| r.join(", ")).unwrap_or_default();
        let mut before: Vec<String> = lines.drain(..i).collect();
        if before.len() >= 3 && before.last().is_some_and(|l| l.len() <= 3 && !has_digit(l)) {
            a.region = before.pop().unwrap_or_default();
        }
        a.city = before.pop().unwrap_or_default();
        a.street = before;
        return a;
    }
    if let Some(i) = lines
        .iter()
        .rposition(|l| city_line(l).is_some())
        .filter(|&i| i >= 1)
    {
        let (city, region, postcode) = city_line(&lines[i]).unwrap_or_default();
        a.city = city;
        a.region = region;
        a.postcode = postcode;
        a.country = lines[i + 1..].join(", ");
        lines.truncate(i);
        a.street = lines;
        return a;
    }
    // No postal code: "street, …, city, country" is too ambiguous to guess
    // beyond a trailing country after three or more lines.
    if lines.len() >= 3 && lines.last().is_some_and(|l| !has_digit(l)) {
        a.country = lines.pop().unwrap_or_default();
        a.city = lines.pop().unwrap_or_default();
    }
    a.street = lines;
    a
}

pub fn identity(e: &Entry) -> Option<Identity> {
    if e.kind != EntryKind::Identity {
        return None;
    }
    let get = |labels: &[&str], hints: &[&str]| field(e, labels, hints).unwrap_or("").to_string();
    let name = get(&["Full name"], &["name", "όνομα"]);
    let (given, middle, family) = split_name(&name);
    let mut address = split_address(&get(
        &["Address"],
        &["address", "street", "διεύθυνση", "οδός"],
    ));
    let set = |slot: &mut String, labels: &[&str], hints: &[&str]| {
        let v = get(labels, hints);
        if !v.is_empty() {
            *slot = v;
        }
    };
    set(&mut address.city, &["City"], &["city", "town", "πόλη"]);
    set(
        &mut address.region,
        &["State / region"],
        &[
            "state",
            "region",
            "province",
            "county",
            "νομός",
            "περιφέρεια",
        ],
    );
    set(
        &mut address.postcode,
        &["Postal code"],
        &[
            "postal",
            "postcode",
            "post code",
            "zip",
            "ταχυδρομικός",
            "τ.κ",
        ],
    );
    set(&mut address.country, &["Country"], &["country", "χώρα"]);
    Some(Identity {
        name,
        given,
        middle,
        family,
        email: get(&["Email"], &["email", "e-mail"]),
        phone: get(
            &["Phone"],
            &["phone", "mobile", "tel", "τηλέφωνο", "κινητό"],
        ),
        street: address.street,
        city: address.city,
        region: address.region,
        postcode: address.postcode,
        country: address.country,
    })
}

/// An identity for lists: the name and the city, or the email.
pub fn identity_summary(e: &Entry) -> String {
    let Some(id) = identity(e) else {
        return String::new();
    };
    [id.name.as_str(), id.city.as_str(), id.email.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .take(2)
        .collect::<Vec<_>>()
        .join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Field, FieldKind};

    fn set(e: &mut Entry, label: &str, value: &str) {
        match e.fields.iter_mut().find(|f| f.label == label) {
            Some(f) => f.value = value.into(),
            None => e
                .fields
                .push(Field::with_value(label, FieldKind::Text, value)),
        }
    }

    #[test]
    fn brands_from_numbers() {
        assert_eq!(card_brand("4242424242424242"), "visa");
        assert_eq!(card_brand("5555555555554444"), "mastercard");
        assert_eq!(card_brand("2223003122003222"), "mastercard");
        assert_eq!(card_brand("378282246310005"), "amex");
        assert_eq!(card_brand("6011111111111117"), "discover");
        assert_eq!(card_brand("3056930009020004"), "diners");
        assert_eq!(card_brand("3566002020360505"), "jcb");
        assert_eq!(card_brand("6200000000000005"), "unionpay");
        assert_eq!(card_brand("12"), "");
        assert_eq!(card_brand(""), "");
    }

    #[test]
    fn cards_are_read_from_their_fields() {
        let mut e = Entry::new(EntryKind::CreditCard);
        set(&mut e, "Cardholder name", "Jane Public");
        set(&mut e, "Card number", "4242 4242 4242 4242");
        set(&mut e, "Expiry (MM/YY)", "8/27");
        set(&mut e, "Security code (CVV)", "123");
        let c = card(&e).unwrap();
        assert_eq!(c.name, "Jane Public");
        assert_eq!(c.number.as_str(), "4242424242424242");
        assert_eq!((c.month.as_str(), c.year.as_str()), ("08", "2027"));
        assert_eq!(c.code, "123");
        assert_eq!(c.brand, "visa");
        assert_eq!(card_summary(&e), "Visa •••• 4242 · 08/27");
        assert!(card(&Entry::new(EntryKind::Login)).is_none());

        // Fields named by hand.
        let mut e = Entry::new(EntryKind::CreditCard);
        e.fields.clear();
        set(&mut e, "Name on card", "J Public");
        set(&mut e, "Number", "5555-5555-5555-4444");
        set(&mut e, "CVC", "999");
        let c = card(&e).unwrap();
        assert_eq!(
            (c.name, c.number.as_str(), c.code),
            ("J Public", "5555555555554444", "999")
        );
        assert_eq!(c.month, "");
        assert_eq!(card_summary(&e), "Mastercard •••• 4444");
    }

    #[test]
    fn names_are_split() {
        let s = |a: &str, b: &str, c: &str| (a.to_string(), b.to_string(), c.to_string());
        assert_eq!(split_name("Dr. Jane Q. Public"), s("Jane", "Q.", "Public"));
        assert_eq!(
            split_name("Γιώργος Παπαδόπουλος"),
            s("Γιώργος", "", "Παπαδόπουλος")
        );
        assert_eq!(split_name("Cher"), s("Cher", "", ""));
        assert_eq!(split_name("Mr"), s("Mr", "", ""));
        assert_eq!(split_name("  "), s("", "", ""));
    }

    fn addr(street: &[&str], city: &str, region: &str, postcode: &str, country: &str) -> Address {
        Address {
            street: street.iter().map(|s| s.to_string()).collect(),
            city: city.into(),
            region: region.into(),
            postcode: postcode.into(),
            country: country.into(),
        }
    }

    #[test]
    fn addresses_are_taken_apart() {
        assert_eq!(
            split_address("Ερμού 12\n105 63 Αθήνα\nΕλλάδα"),
            addr(&["Ερμού 12"], "Αθήνα", "", "105 63", "Ελλάδα")
        );
        assert_eq!(
            split_address("1 Main St\nApt 4\nSpringfield, IL 62701"),
            addr(&["1 Main St", "Apt 4"], "Springfield", "IL", "62701", "")
        );
        assert_eq!(
            split_address("10 Downing Street\nLondon SW1A 2AA\nUnited Kingdom"),
            addr(
                &["10 Downing Street"],
                "London",
                "",
                "SW1A 2AA",
                "United Kingdom"
            )
        );
        assert_eq!(
            split_address("Damrak 1\n1012 AB Amsterdam"),
            addr(&["Damrak 1"], "Amsterdam", "", "1012 AB", "")
        );
        assert_eq!(
            split_address("Hauptstraße 5\n10115 Berlin\nDeutschland"),
            addr(&["Hauptstraße 5"], "Berlin", "", "10115", "Deutschland")
        );
        // Written by older versions' Bitwarden import: one part per line.
        assert_eq!(
            split_address("1 Main St\nApt 4\nSpringfield\nIL\n62701\nUSA"),
            addr(&["1 Main St", "Apt 4"], "Springfield", "IL", "62701", "USA")
        );
        assert_eq!(
            split_address("1 Main St"),
            addr(&["1 Main St"], "", "", "", "")
        );
        assert_eq!(
            split_address("Rose Cottage\nLittle Village\nEngland"),
            addr(&["Rose Cottage"], "Little Village", "", "", "England")
        );
        assert_eq!(split_address(""), Address::default());
    }

    #[test]
    fn identities_prefer_their_own_fields() {
        let mut e = Entry::new(EntryKind::Identity);
        set(&mut e, "Full name", "Jane Public");
        set(&mut e, "Email", "jane@example.com");
        set(&mut e, "Phone", "+30 210 0000000");
        set(&mut e, "Address", "Ερμού 12\n105 63 Αθήνα");
        set(&mut e, "Country", "Greece");
        let id = identity(&e).unwrap();
        assert_eq!((id.given.as_str(), id.family.as_str()), ("Jane", "Public"));
        assert_eq!(id.street, vec!["Ερμού 12".to_string()]);
        assert_eq!(
            (id.city.as_str(), id.postcode.as_str()),
            ("Αθήνα", "105 63")
        );
        assert_eq!(id.country, "Greece");
        assert_eq!(id.phone, "+30 210 0000000");
        assert_eq!(identity_summary(&e), "Jane Public · Αθήνα");

        set(&mut e, "City", "Athens");
        assert_eq!(identity(&e).unwrap().city, "Athens");
        assert!(identity(&Entry::new(EntryKind::CreditCard)).is_none());
    }
}
