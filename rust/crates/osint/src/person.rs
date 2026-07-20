use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{FindingKind, OsintFinding, OsintSource, Reliability};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedName {
    pub full: String,
    pub first: Option<String>,
    pub middle: Option<String>,
    pub last: Option<String>,
    pub prefix: Option<String>,
    pub suffix: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NameParser;

impl NameParser {
    pub fn parse(full: &str) -> ParsedName {
        let mut first = None;
        let mut middle = None;
        let mut last = None;
        let mut prefix = None;
        let mut suffix = None;

        let trimmed = full.trim();
        let has_comma = trimmed.contains(',');

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            return ParsedName { full: full.into(), first: None, middle: None, last: None, prefix: None, suffix: None };
        }

        let mut remaining: Vec<&str> = Vec::new();
        for p in &parts {
            remaining.push(p);
        }

        let prefixes = ["mr", "mrs", "ms", "miss", "dr", "prof", "rev", "hon", "sir", "madam",
                        "sr", "dona", "doña", "dona.", "doña.", "lic", "lic.", "ing", "ing."];
        let suffixes = ["jr", "sr", "ii", "iii", "iv", "v", "phd", "md", "esq", "cpa",
                        "jr.", "sr.", "ph.d.", "m.d.", "esq."];

        if has_comma {
            let raw_parts: Vec<&str> = trimmed.splitn(2, ',').collect();
            if raw_parts.len() == 2 {
                let last_part = raw_parts[0].trim();
                let rest = raw_parts[1].trim();
                last = Some(last_part.to_string());
                let rest_parts: Vec<&str> = rest.split_whitespace().collect();
                let mut iter = rest_parts.into_iter();

                if let Some(p) = iter.next() {
                    let lower = p.to_lowercase();
                    if prefixes.contains(&lower.as_str()) {
                        prefix = Some(p.to_string());
                        if let Some(n) = iter.next() { first = Some(n.to_string()); }
                    } else {
                        first = Some(p.to_string());
                    }
                }
                let mid: Vec<String> = iter.map(|s| s.to_string()).collect();
                if !mid.is_empty() {
                    middle = Some(mid.join(" "));
                }
                if let Some(ref m) = middle {
                    let lower_m = m.to_lowercase();
                    if suffixes.contains(&lower_m.as_str()) {
                        suffix = Some(m.clone());
                        middle = None;
                    }
                }
            }
        } else {
            let mut i = 0;

            if i < parts.len() {
                let lower = parts[i].to_lowercase().trim_end_matches('.').to_string();
                if prefixes.contains(&lower.as_str()) {
                    prefix = Some(parts[i].to_string());
                    i += 1;
                }
            }

            if i < parts.len() {
                first = Some(parts[i].to_string());
                i += 1;
            }

            let mut collected: Vec<&str> = Vec::new();
            while i < parts.len() - 1 {
                let lower = parts[i].to_lowercase().trim_end_matches('.').to_string();
                if !suffixes.contains(&lower.as_str()) {
                    collected.push(parts[i]);
                } else {
                    suffix = Some(parts[i].to_string());
                    collected.clear();
                    break;
                }
                i += 1;
            }

            if i < parts.len() {
                let lower = parts[i].to_lowercase().trim_end_matches('.').to_string();
                if suffixes.contains(&lower.as_str()) {
                    suffix = Some(parts[i].to_string());
                    if collected.len() == 1 {
                        last = Some(collected[0].to_string());
                    } else if collected.len() > 1 {
                        middle = Some(collected[..collected.len()-1].join(" "));
                        last = Some(collected[collected.len()-1].to_string());
                    }
                } else {
                    if !collected.is_empty() {
                        middle = Some(collected.join(" "));
                    }
                    last = Some(parts[i].to_string());
                }
            } else if !collected.is_empty() {
                if collected.len() > 1 {
                    middle = Some(collected[..collected.len()-1].join(" "));
                    last = Some(collected[collected.len()-1].to_string());
                } else {
                    last = Some(collected[0].to_string());
                }
            }
        }

        ParsedName { full: full.into(), first, middle, last, prefix, suffix }
    }

    pub fn analyze(name: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let parsed = Self::parse(name);

        if let Some(ref first) = parsed.first {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "name/first".into(),
                    reliability: Reliability::High,
                    url: None,
                },
                kind: FindingKind::Custom("PersonName".into()),
                value: format!("First name: {}", first),
                context: Some(format!("Extracted from: {}", name)),
                confidence: 0.95,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }
        if let Some(ref last) = parsed.last {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "name/last".into(),
                    reliability: Reliability::High,
                    url: None,
                },
                kind: FindingKind::Custom("PersonName".into()),
                value: format!("Last name: {}", last),
                context: Some(format!("Extracted from: {}", name)),
                confidence: 0.95,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }
        if let Some(ref prefix) = parsed.prefix {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "name/prefix".into(),
                    reliability: Reliability::High,
                    url: None,
                },
                kind: FindingKind::Custom("PersonName".into()),
                value: format!("Prefix/Title: {}", prefix),
                context: None,
                confidence: 0.9,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }
        if let Some(ref suffix) = parsed.suffix {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "name/suffix".into(),
                    reliability: Reliability::High,
                    url: None,
                },
                kind: FindingKind::Custom("PersonName".into()),
                value: format!("Suffix: {}", suffix),
                context: None,
                confidence: 0.9,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        let initials: String = name.split_whitespace()
            .filter_map(|w| w.chars().next().filter(|c| c.is_ascii_alphabetic()))
            .collect::<Vec<char>>()
            .chunks(2)
            .map(|c| c.iter().collect::<String>())
            .collect();
        if initials.len() >= 2 {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "name/initials".into(),
                    reliability: Reliability::High,
                    url: None,
                },
                kind: FindingKind::Custom("PersonName".into()),
                value: format!("Initials: {}", initials.to_uppercase()),
                context: Some(format!("Derived from: {}", name)),
                confidence: 0.8,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        findings
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhoneInfo {
    pub raw: String,
    pub normalized: String,
    pub country_code: Option<String>,
    pub national: Option<String>,
    pub carrier: Option<String>,
    pub country_name: Option<String>,
    pub is_valid: bool,
}

#[derive(Debug, Clone)]
pub struct PhoneOSINT;

impl PhoneOSINT {
    pub fn validate(phone: &str) -> PhoneInfo {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return PhoneInfo {
                raw: phone.into(),
                normalized: String::new(),
                country_code: None,
                national: None,
                carrier: None,
                country_name: None,
                is_valid: false,
            };
        }

        let (country_code, national, country_name) = Self::detect_country(&digits);

        PhoneInfo {
            raw: phone.into(),
            normalized: Self::format_e164(&country_code, &national),
            country_code,
            national: Some(national),
            carrier: Self::detect_carrier(&digits),
            country_name,
            is_valid: true,
        }
    }

    fn detect_country(digits: &str) -> (Option<String>, String, Option<String>) {
        let country_codes: Vec<(&str, &str, &str)> = vec![
            ("1", "US", "United States"),
            ("1", "CA", "Canada"),
            ("7", "RU", "Russia"),
            ("20", "EG", "Egypt"),
            ("27", "ZA", "South Africa"),
            ("30", "GR", "Greece"),
            ("31", "NL", "Netherlands"),
            ("32", "BE", "Belgium"),
            ("33", "FR", "France"),
            ("34", "ES", "Spain"),
            ("36", "HU", "Hungary"),
            ("39", "IT", "Italy"),
            ("40", "RO", "Romania"),
            ("41", "CH", "Switzerland"),
            ("43", "AT", "Austria"),
            ("44", "GB", "United Kingdom"),
            ("45", "DK", "Denmark"),
            ("46", "SE", "Sweden"),
            ("47", "NO", "Norway"),
            ("48", "PL", "Poland"),
            ("49", "DE", "Germany"),
            ("51", "PE", "Peru"),
            ("52", "MX", "Mexico"),
            ("53", "CU", "Cuba"),
            ("54", "AR", "Argentina"),
            ("55", "BR", "Brazil"),
            ("56", "CL", "Chile"),
            ("57", "CO", "Colombia"),
            ("58", "VE", "Venezuela"),
            ("60", "MY", "Malaysia"),
            ("61", "AU", "Australia"),
            ("62", "ID", "Indonesia"),
            ("63", "PH", "Philippines"),
            ("64", "NZ", "New Zealand"),
            ("65", "SG", "Singapore"),
            ("66", "TH", "Thailand"),
            ("81", "JP", "Japan"),
            ("82", "KR", "South Korea"),
            ("84", "VN", "Vietnam"),
            ("86", "CN", "China"),
            ("90", "TR", "Turkey"),
            ("91", "IN", "India"),
            ("92", "PK", "Pakistan"),
            ("93", "AF", "Afghanistan"),
            ("94", "LK", "Sri Lanka"),
            ("95", "MM", "Myanmar"),
            ("98", "IR", "Iran"),
            ("212", "MA", "Morocco"),
            ("213", "DZ", "Algeria"),
            ("216", "TN", "Tunisia"),
            ("220", "GM", "Gambia"),
            ("221", "SN", "Senegal"),
            ("233", "GH", "Ghana"),
            ("234", "NG", "Nigeria"),
            ("254", "KE", "Kenya"),
            ("255", "TZ", "Tanzania"),
            ("256", "UG", "Uganda"),
            ("260", "ZM", "Zambia"),
            ("263", "ZW", "Zimbabwe"),
            ("351", "PT", "Portugal"),
            ("352", "LU", "Luxembourg"),
            ("353", "IE", "Ireland"),
            ("354", "IS", "Iceland"),
            ("355", "AL", "Albania"),
            ("356", "MT", "Malta"),
            ("357", "CY", "Cyprus"),
            ("358", "FI", "Finland"),
            ("359", "BG", "Bulgaria"),
            ("370", "LT", "Lithuania"),
            ("371", "LV", "Latvia"),
            ("372", "EE", "Estonia"),
            ("373", "MD", "Moldova"),
            ("374", "AM", "Armenia"),
            ("375", "BY", "Belarus"),
            ("376", "AD", "Andorra"),
            ("380", "UA", "Ukraine"),
            ("381", "RS", "Serbia"),
            ("382", "ME", "Montenegro"),
            ("385", "HR", "Croatia"),
            ("386", "SI", "Slovenia"),
            ("387", "BA", "Bosnia"),
            ("389", "MK", "North Macedonia"),
            ("420", "CZ", "Czech Republic"),
            ("421", "SK", "Slovakia"),
            ("423", "LI", "Liechtenstein"),
            ("501", "BZ", "Belize"),
            ("502", "GT", "Guatemala"),
            ("503", "SV", "El Salvador"),
            ("504", "HN", "Honduras"),
            ("505", "NI", "Nicaragua"),
            ("506", "CR", "Costa Rica"),
            ("507", "PA", "Panama"),
            ("509", "HT", "Haiti"),
            ("591", "BO", "Bolivia"),
            ("592", "GY", "Guyana"),
            ("593", "EC", "Ecuador"),
            ("594", "GF", "French Guiana"),
            ("595", "PY", "Paraguay"),
            ("596", "MQ", "Martinique"),
            ("597", "SR", "Suriname"),
            ("598", "UY", "Uruguay"),
            ("599", "BQ", "Caribbean Netherlands"),
            ("886", "TW", "Taiwan"),
            ("960", "MV", "Maldives"),
            ("961", "LB", "Lebanon"),
            ("962", "JO", "Jordan"),
            ("963", "SY", "Syria"),
            ("964", "IQ", "Iraq"),
            ("965", "KW", "Kuwait"),
            ("966", "SA", "Saudi Arabia"),
            ("967", "YE", "Yemen"),
            ("968", "OM", "Oman"),
            ("970", "PS", "Palestine"),
            ("971", "AE", "UAE"),
            ("972", "IL", "Israel"),
            ("973", "BH", "Bahrain"),
            ("974", "QA", "Qatar"),
            ("975", "BT", "Bhutan"),
            ("976", "MN", "Mongolia"),
            ("977", "NP", "Nepal"),
            ("992", "TJ", "Tajikistan"),
            ("993", "TM", "Turkmenistan"),
            ("994", "AZ", "Azerbaijan"),
            ("995", "GE", "Georgia"),
            ("996", "KG", "Kyrgyzstan"),
            ("998", "UZ", "Uzbekistan"),
        ];

        for (code, _iso, name) in &country_codes {
            if let Some(stripped) = digits.strip_prefix(code) {
                let national = stripped.to_string();
                return (Some(code.to_string()), national, Some(name.to_string()));
            }
        }

        (None, digits.to_string(), None)
    }

    fn detect_carrier(digits: &str) -> Option<String> {
        if digits.starts_with("58") && digits.len() >= 10
            && (digits.len() == 11 || digits.len() == 12 || digits.len() == 13) {
                let national = if digits.len() > 10 { &digits[2..] } else { digits };
                if national.starts_with("412") || national.starts_with("414") || national.starts_with("416") {
                    return Some("Movistar".into());
                }
                if national.starts_with("424") || national.starts_with("426") || national.starts_with("426") {
                    return Some("Movilnet".into());
                }
                if national.starts_with("414") || national.starts_with("424") || national.starts_with("424") {
                    return Some("Digitel".into());
                }
            }
        if digits.starts_with("52") && digits.len() >= 12 {
            return Some("Mexico (generic)".into());
        }
        if digits.starts_with("1") && digits.len() == 11 {
            let prefix = &digits[1..4];
            return match prefix {
                "201" | "202" | "203" | "205" | "206" | "207" | "208" | "209" | "210" | "212" |
                "213" | "214" | "215" | "216" | "217" | "218" | "219" | "220" | "224" | "225" |
                "228" | "229" | "231" | "234" | "239" | "240" | "248" | "251" | "252" | "253" |
                "254" | "256" | "260" | "262" | "267" | "269" | "270" | "272" | "274" | "276" |
                "281" | "283" | "301" | "302" | "303" | "304" | "305" | "307" | "308" | "309" |
                "310" | "312" | "313" | "314" | "315" | "316" | "317" | "318" | "319" | "320" |
                "321" | "323" | "325" | "327" | "330" | "331" | "332" | "334" | "336" | "337" |
                "339" | "340" | "341" | "346" | "347" | "351" | "352" | "360" | "361" | "364" |
                "380" | "385" | "386" | "401" | "402" | "404" | "405" | "406" | "407" | "408" |
                "409" | "410" | "412" | "413" | "414" | "415" | "417" | "419" | "423" | "424" |
                "425" | "430" | "432" | "434" | "435" | "440" | "442" | "443" | "447" | "458" |
                "459" | "469" | "470" | "475" | "478" | "479" | "480" | "484" | "501" | "502" |
                "503" | "504" | "505" | "507" | "508" | "509" | "510" | "512" | "513" | "515" |
                "516" | "517" | "518" | "520" | "530" | "531" | "534" | "539" | "540" | "541" |
                "551" | "559" | "561" | "562" | "563" | "564" | "567" | "570" | "571" | "573" |
                "574" | "575" | "580" | "585" | "586" | "601" | "602" | "603" | "605" | "606" |
                "607" | "608" | "609" | "610" | "612" | "614" | "615" | "616" | "617" | "618" |
                "619" | "620" | "623" | "626" | "628" | "629" | "630" | "631" | "636" | "640" |
                "641" | "646" | "650" | "651" | "657" | "660" | "661" | "662" | "667" | "669" |
                "670" | "671" | "678" | "680" | "681" | "682" | "701" | "702" | "703" | "704" |
                "706" | "707" | "708" | "712" | "713" | "714" | "715" | "716" | "717" | "718" |
                "719" | "720" | "724" | "725" | "727" | "730" | "731" | "732" | "734" | "737" |
                "740" | "743" | "747" | "754" | "757" | "760" | "762" | "763" | "765" | "769" |
                "770" | "771" | "772" | "773" | "774" | "775" | "779" | "781" | "785" | "786" |
                "801" | "802" | "803" | "804" | "805" | "806" | "808" | "810" | "812" | "813" |
                "814" | "815" | "816" | "817" | "818" | "828" | "830" | "831" | "832" | "835" |
                "838" | "840" | "843" | "845" | "847" | "848" | "850" | "854" | "856" | "857" |
                "858" | "859" | "860" | "862" | "863" | "864" | "865" | "870" | "872" | "878" |
                "901" | "903" | "904" | "906" | "907" | "908" | "909" | "910" | "912" | "913" |
                "914" | "915" | "916" | "917" | "918" | "919" | "920" | "925" | "928" | "929" |
                "930" | "931" | "934" | "936" | "937" | "938" | "940" | "941" | "947" | "949" |
                "951" | "952" | "954" | "956" | "959" | "970" | "971" | "972" | "973" | "978" |
                "979" | "980" | "984" | "985" | "986" | "989" => Some("US (generic)".into()),
                _ => None,
            };
        }
        if digits.starts_with("44") {
            return Some("UK (generic)".into());
        }
        if digits.starts_with("33") {
            return Some("France (generic)".into());
        }
        if digits.starts_with("49") {
            return Some("Germany (generic)".into());
        }
        if digits.starts_with("34") {
            return Some("Spain (generic)".into());
        }
        None
    }

    fn format_e164(country_code: &Option<String>, national: &str) -> String {
        match country_code {
            Some(cc) => format!("+{}{}", cc, national),
            None => national.to_string(),
        }
    }

    pub fn analyze(phone: &str) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let info = Self::validate(phone);
        let normalized = phone;

        findings.push(OsintFinding {
            source: OsintSource {
                name: "phone/raw".into(),
                reliability: Reliability::High,
                url: None,
            },
            kind: FindingKind::PhoneNumber,
            value: format!("Phone: {}", info.raw),
            context: Some(format!("Normalized: {}", info.normalized)),
            confidence: if info.is_valid { 0.9 } else { 0.3 },
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        });

        if info.is_valid {
            if let Some(ref cc) = info.country_code {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "phone/country".into(),
                        reliability: Reliability::High,
                        url: None,
                    },
                    kind: FindingKind::Custom("PhoneCountry".into()),
                    value: format!("Country code: +{}", cc),
                    context: info.country_name.as_ref().map(|n| format!("Country: {}", n)),
                    confidence: 0.9,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }

            if let Some(ref carrier) = info.carrier {
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: "phone/carrier".into(),
                        reliability: Reliability::Medium,
                        url: None,
                    },
                    kind: FindingKind::Custom("PhoneCarrier".into()),
                    value: format!("Carrier: {}", carrier),
                    context: Some(format!("Inferred from prefix of {}", normalized)),
                    confidence: 0.6,
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }

            let variations = Self::generate_variations(&info.normalized);
            for (label, variant) in &variations {
                if *variant != info.normalized {
                    findings.push(OsintFinding {
                        source: OsintSource {
                            name: "phone/variation".into(),
                            reliability: Reliability::High,
                            url: None,
                        },
                        kind: FindingKind::PhoneNumber,
                        value: format!("Phone ({})", label),
                        context: Some(variant.clone()),
                        confidence: 0.95,
                        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    });
                }
            }
        }

        findings
    }

    fn generate_variations(e164: &str) -> Vec<(&'static str, String)> {
        let digits: String = e164.chars().filter(|c| c.is_ascii_digit()).collect();
        vec![
            ("E.164", e164.to_string()),
            ("digits", digits.clone()),
            ("spaced", Self::spaced(&digits)),
            ("dashed", Self::dashed(&digits)),
        ]
    }

    fn spaced(digits: &str) -> String {
        let mut result = String::new();
        for (i, c) in digits.chars().enumerate() {
            if i > 0 && (i % 3 == 0) {
                result.push(' ');
            }
            result.push(c);
        }
        result
    }

    fn dashed(digits: &str) -> String {
        let mut result = String::new();
        for (i, c) in digits.chars().enumerate() {
            if i > 0 && (i % 3 == 0) {
                result.push('-');
            }
            result.push(c);
        }
        result
    }
}

#[derive(Debug, Clone)]
pub struct PersonSearcher;

impl PersonSearcher {
    pub fn search_urls(name: &str) -> Vec<OsintFinding> {
        let encoded: String = name.split_whitespace().collect::<Vec<&str>>().join("+");
        let encoded_dash: String = name.split_whitespace().collect::<Vec<&str>>().join("-");
        let encoded_full: String = name.replace(' ', "+");

        let engines: Vec<(&str, String)> = vec![
            ("Pipl", format!("https://pipl.com/search/?q={}", encoded_full)),
            ("Spokeo", format!("https://www.spokeo.com/{}", encoded_dash)),
            ("Whitepages", format!("https://www.whitepages.com/name/{}", encoded_dash)),
            ("BeenVerified", format!("https://www.beenverified.com/people/{}", encoded)),
            ("Intelius", format!("https://www.intelius.com/people/{}", encoded)),
            ("PeekYou", format!("https://peekyou.com/{}", encoded)),
            ("Radaris", format!("https://radaris.com/search?name={}", encoded_full)),
            ("ZabaSearch", format!("https://www.zabasearch.com/people/{}", encoded)),
            ("411", format!("https://www.411.com/name/{}", encoded_dash)),
            ("ThatsThem", format!("https://thatsthem.com/name/{}", encoded)),
            ("TruePeopleSearch", format!("https://www.truepeoplesearch.com/results?name={}", encoded_full)),
            ("FamilyTreeNow", format!("https://www.familytreenow.com/search/people/results?first={}&last={}", 
                name.split_whitespace().next().unwrap_or(""), 
                name.split_whitespace().last().unwrap_or(""))),
        ];

        let mut findings = Vec::new();
        for (engine, url) in engines {
            findings.push(OsintFinding {
                source: OsintSource {
                    name: format!("people/{}", engine),
                    reliability: Reliability::Medium,
                    url: Some(url),
                },
                kind: FindingKind::Url,
                value: format!("{} search: {}", engine, name),
                context: Some(format!("Search URL for '{}' on {}", name, engine)),
                confidence: 0.5,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }
        findings
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityData {
    pub names: Vec<String>,
    pub usernames: Vec<String>,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub urls: Vec<String>,
    pub addresses: Vec<String>,
    pub organizations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IdentityCorrelator;

impl IdentityCorrelator {
    pub fn correlate(data: &IdentityData) -> Vec<OsintFinding> {
        let mut findings = Vec::new();
        let mut total_points = 0usize;
        let mut matched_points = 0usize;

        if !data.names.is_empty() {
            total_points += 1;
            matched_points += 1;
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "identity/name".into(),
                    reliability: Reliability::High,
                    url: None,
                },
                kind: FindingKind::Custom("Identity".into()),
                value: format!("Names: {}", data.names.join(", ")),
                context: Some("Confirmed identity anchor".into()),
                confidence: 0.95,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        if !data.emails.is_empty() {
            total_points += 1;
            matched_points += 1;
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "identity/email".into(),
                    reliability: Reliability::Medium,
                    url: None,
                },
                kind: FindingKind::Custom("Identity".into()),
                value: format!("Emails: {}", data.emails.join(", ")),
                context: Some("Email addresses linked to identity".into()),
                confidence: 0.8,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        if !data.usernames.is_empty() {
            total_points += 1;
            matched_points += 1;
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "identity/username".into(),
                    reliability: Reliability::Medium,
                    url: None,
                },
                kind: FindingKind::Custom("Identity".into()),
                value: format!("Usernames: {}", data.usernames.join(", ")),
                context: Some("Usernames linked to identity".into()),
                confidence: 0.7,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        if !data.phones.is_empty() {
            total_points += 1;
            matched_points += 1;
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "identity/phone".into(),
                    reliability: Reliability::Medium,
                    url: None,
                },
                kind: FindingKind::Custom("Identity".into()),
                value: format!("Phones: {}", data.phones.join(", ")),
                context: Some("Phone numbers linked to identity".into()),
                confidence: 0.75,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        if !data.urls.is_empty() {
            total_points += 1;
            matched_points += 1;
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "identity/url".into(),
                    reliability: Reliability::Low,
                    url: None,
                },
                kind: FindingKind::Custom("Identity".into()),
                value: format!("URLs: {}", data.urls.join(", ")),
                context: Some("Websites linked to identity".into()),
                confidence: 0.5,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        if !data.organizations.is_empty() {
            total_points += 1;
            matched_points += 1;
            findings.push(OsintFinding {
                source: OsintSource {
                    name: "identity/org".into(),
                    reliability: Reliability::Low,
                    url: None,
                },
                kind: FindingKind::Custom("Identity".into()),
                value: format!("Organizations: {}", data.organizations.join(", ")),
                context: Some("Organizations linked to identity".into()),
                confidence: 0.5,
                timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
        }

        let overall_confidence = if total_points > 0 {
            matched_points as f64 / total_points as f64
        } else {
            0.0
        };

        findings.push(OsintFinding {
            source: OsintSource {
                name: "identity/summary".into(),
                reliability: Reliability::Medium,
                url: None,
            },
            kind: FindingKind::Custom("Identity".into()),
            value: format!("Identity correlation: {} data points", total_points),
            context: Some(format!(
                "Overall confidence: {:.1}%. {} of {} data point types available",
                overall_confidence * 100.0,
                matched_points, total_points
            )),
            confidence: overall_confidence,
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        });

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_first_last() {
        let p = NameParser::parse("John Smith");
        assert_eq!(p.first.as_deref(), Some("John"));
        assert_eq!(p.last.as_deref(), Some("Smith"));
    }

    #[test]
    fn parses_comma_format() {
        let p = NameParser::parse("Smith, John");
        assert_eq!(p.first.as_deref(), Some("John"));
        assert_eq!(p.last.as_deref(), Some("Smith"));
    }

    #[test]
    fn parses_with_prefix() {
        let p = NameParser::parse("Dr. Jane Doe");
        assert_eq!(p.prefix.as_deref(), Some("Dr."));
        assert_eq!(p.first.as_deref(), Some("Jane"));
        assert_eq!(p.last.as_deref(), Some("Doe"));
    }

    #[test]
    fn parses_with_suffix() {
        let p = NameParser::parse("John Smith Jr.");
        assert_eq!(p.first.as_deref(), Some("John"));
        assert_eq!(p.last.as_deref(), Some("Smith"));
        assert_eq!(p.suffix.as_deref(), Some("Jr."));
    }

    #[test]
    fn parses_three_part() {
        let p = NameParser::parse("John Michael Smith");
        assert_eq!(p.first.as_deref(), Some("John"));
        assert_eq!(p.middle.as_deref(), Some("Michael"));
        assert_eq!(p.last.as_deref(), Some("Smith"));
    }

    #[test]
    fn returns_initials() {
        let findings = NameParser::analyze("John Michael Smith");
        assert!(findings.iter().any(|f| f.value.contains("JMS")));
    }

    #[test]
    fn validates_phone_us() {
        let info = PhoneOSINT::validate("+14155551234");
        assert!(info.is_valid);
        assert_eq!(info.country_code.as_deref(), Some("1"));
        assert_eq!(info.country_name.as_deref(), Some("United States"));
    }

    #[test]
    fn validates_phone_venezuela() {
        let info = PhoneOSINT::validate("+584121234567");
        assert!(info.is_valid);
        assert_eq!(info.country_code.as_deref(), Some("58"));
        assert_eq!(info.country_name.as_deref(), Some("Venezuela"));
    }

    #[test]
    fn detects_movistar_venezuela() {
        let info = PhoneOSINT::validate("+584121234567");
        assert_eq!(info.carrier.as_deref(), Some("Movistar"));
    }

    #[test]
    fn phone_invalid_no_digits() {
        let info = PhoneOSINT::validate("abc");
        assert!(!info.is_valid);
    }

    #[test]
    fn phone_analyze_returns_findings() {
        let findings = PhoneOSINT::analyze("+14155551234");
        assert!(findings.len() >= 2);
        assert!(findings.iter().any(|f| f.kind == FindingKind::PhoneNumber));
    }

    #[test]
    fn person_searcher_returns_urls() {
        let findings = PersonSearcher::search_urls("John Doe");
        assert!(findings.len() >= 10);
        assert!(findings.iter().any(|f| f.value.contains("Pipl")));
        assert!(findings.iter().any(|f| f.value.contains("Spokeo")));
    }

    #[test]
    fn identity_correlator_empty() {
        let data = IdentityData {
            names: vec![],
            usernames: vec![],
            emails: vec![],
            phones: vec![],
            urls: vec![],
            addresses: vec![],
            organizations: vec![],
        };
        let findings = IdentityCorrelator::correlate(&data);
        let summary: Vec<_> = findings.iter().filter(|f| f.source.name == "identity/summary").collect();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].confidence, 0.0);
    }

    #[test]
    fn identity_correlator_with_data() {
        let data = IdentityData {
            names: vec!["John Doe".into()],
            usernames: vec!["johndoe".into()],
            emails: vec!["john@example.com".into()],
            phones: vec![],
            urls: vec![],
            addresses: vec![],
            organizations: vec!["Acme Corp".into()],
        };
        let findings = IdentityCorrelator::correlate(&data);
        assert!(findings.len() >= 5);
        let summary: Vec<_> = findings.iter().filter(|f| f.source.name == "identity/summary").collect();
        assert!(summary[0].confidence > 0.0);
    }

    #[test]
    fn parses_spanish_name() {
        let p = NameParser::parse("Juan Carlos Rodríguez López");
        assert_eq!(p.first.as_deref(), Some("Juan"));
        assert!(p.last.is_some());
    }

    #[test]
    fn phone_uk_detected() {
        let info = PhoneOSINT::validate("+442071234567");
        assert!(info.is_valid);
        assert_eq!(info.country_code.as_deref(), Some("44"));
    }

    #[test]
    fn phone_variations_generated() {
        let info = PhoneOSINT::validate("+14155551234");
        assert!(info.normalized.starts_with('+'));
    }

    #[test]
    fn name_analyze_returns_name_findings() {
        let findings = NameParser::analyze("Robert Downey Jr.");
        assert!(findings.iter().any(|f| f.value.contains("Robert")));
        assert!(findings.iter().any(|f| f.value.contains("Suffix")));
    }

    #[test]
    fn parses_empty_string() {
        let p = NameParser::parse("");
        assert!(p.first.is_none());
        assert!(p.last.is_none());
    }

    #[test]
    fn parses_single_name() {
        let p = NameParser::parse("Madonna");
        assert_eq!(p.first.as_deref(), Some("Madonna"));
        assert!(p.last.is_none());
    }

    #[test]
    fn parses_prefix_dr_without_period() {
        let p = NameParser::parse("Dr Jane Doe");
        assert_eq!(p.prefix.as_deref(), Some("Dr"));
        assert_eq!(p.first.as_deref(), Some("Jane"));
    }

    #[test]
    fn parses_comma_with_prefix() {
        let p = NameParser::parse("Doe, Dr Jane");
        assert_eq!(p.last.as_deref(), Some("Doe"));
        assert_eq!(p.prefix.as_deref(), Some("Dr"));
        assert_eq!(p.first.as_deref(), Some("Jane"));
    }

    #[test]
    fn phone_validates_empty() {
        let info = PhoneOSINT::validate("");
        assert!(!info.is_valid);
    }

    #[test]
    fn phone_validates_plus_only() {
        let info = PhoneOSINT::validate("+");
        assert!(!info.is_valid);
    }

    #[test]
    fn phone_detects_france() {
        let info = PhoneOSINT::validate("+33612345678");
        assert!(info.is_valid);
        assert_eq!(info.country_code.as_deref(), Some("33"));
        assert_eq!(info.country_name.as_deref(), Some("France"));
    }

    #[test]
    fn phone_detects_germany() {
        let info = PhoneOSINT::validate("+49170123456");
        assert!(info.is_valid);
        assert_eq!(info.country_code.as_deref(), Some("49"));
        assert_eq!(info.country_name.as_deref(), Some("Germany"));
    }

    #[test]
    fn phone_detects_japan() {
        let info = PhoneOSINT::validate("+81901234567");
        assert!(info.is_valid);
        assert_eq!(info.country_code.as_deref(), Some("81"));
        assert_eq!(info.country_name.as_deref(), Some("Japan"));
    }

    #[test]
    fn phone_detects_india() {
        let info = PhoneOSINT::validate("+919876543210");
        assert!(info.is_valid);
        assert_eq!(info.country_code.as_deref(), Some("91"));
    }

    #[test]
    fn phone_uk_carrier() {
        let info = PhoneOSINT::validate("+447911123456");
        assert!(info.is_valid);
        assert!(info.carrier.is_some());
    }

    #[test]
    fn phone_france_carrier() {
        let info = PhoneOSINT::validate("+33612345678");
        assert!(info.carrier.is_some());
    }

    #[test]
    fn phone_germany_carrier() {
        let info = PhoneOSINT::validate("+49170123456");
        assert!(info.carrier.is_some());
    }

    #[test]
    fn phone_spain_carrier() {
        let info = PhoneOSINT::validate("+34612345678");
        assert!(info.carrier.is_some());
    }

    #[test]
    fn person_searcher_returns_minimum_10() {
        let findings = PersonSearcher::search_urls("Jane Doe");
        assert!(findings.len() >= 10);
    }

    #[test]
    fn identity_correlator_all_fields() {
        let data = IdentityData {
            names: vec!["John Doe".into()],
            usernames: vec!["johndoe".into()],
            emails: vec!["john@example.com".into()],
            phones: vec!["+14155551234".into()],
            urls: vec!["https://example.com".into()],
            addresses: vec!["123 Main St".into()],
            organizations: vec!["Acme Corp".into()],
        };
        let findings = IdentityCorrelator::correlate(&data);
        assert!(findings.len() >= 7);
        let summary = findings.iter().find(|f| f.source.name == "identity/summary").unwrap();
        assert!(summary.confidence > 0.0);
    }

    #[test]
    fn phone_info_struct_fields() {
        let info = PhoneOSINT::validate("+14155551234");
        assert!(!info.raw.is_empty());
        assert!(!info.normalized.is_empty());
    }

    #[test]
    fn parsed_name_struct_serialization() {
        let p = NameParser::parse("John Smith");
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("John"));
        assert!(json.contains("Smith"));
    }

    #[test]
    fn phone_info_serialization() {
        let info = PhoneOSINT::validate("+14155551234");
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("+14155551234"));
    }

    #[test]
    fn identity_data_serialization() {
        let data = IdentityData {
            names: vec!["Test".into()],
            usernames: vec![],
            emails: vec![],
            phones: vec![],
            urls: vec![],
            addresses: vec![],
            organizations: vec![],
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("Test"));
    }
}
