use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{FindingKind, OsintFinding, OsintSource, Reliability};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    GitHub,
    GitLab,
    Bitbucket,
    TwitterX,
    LinkedIn,
    Reddit,
    Instagram,
    Facebook,
    Telegram,
    Discord,
    YouTube,
    TikTok,
    Snapchat,
    Pinterest,
    Tumblr,
    Medium,
    DevTo,
    HackerNews,
    StackOverflow,
    StackExchange,
    Keybase,
    Mastodon,
    Bluesky,
    Threads,
    WhatsApp,
    Signal,
    WeChat,
    QQ,
    VK,
    Odnoklassniki,
    TelegramChannel,
    DiscordServer,
    Slack,
    Matrix,
    Element,
    RocketChat,
    Twitch,
    Kick,
    Rumble,
    Odysee,
    Dailymotion,
    Vimeo,
    Flickr,
    VSCO,
    Behance,
    Dribbble,
    CodePen,
    Replit,
    Glitch,
    Giters,
    SourceForge,
    HuggingFace,
    DockerHub,
    PyPI,
    CratesIO,
    Rubygems,
    NpmJS,
    NuGet,
    Packagist,
    WordPress,
    Blogger,
    Gravatar,
    AboutMe,
    LinkTree,
    BioLink,
    Carrd,
    Hashnode,
    Substack,
    Ghost,
    Patreon,
    KoFi,
    BuyMeACoffee,
    OpenCollective,
    GoFundMe,
    Kickstarter,
    Indiegogo,
    ProductHunt,
    AngelList,
    Crunchbase,
    Bloomberg,
    Forbes,
    DuckDuckGo,
    Custom(String),
}

impl Platform {
    pub fn as_str(&self) -> &str {
        match self {
            Self::GitHub => "GitHub",
            Self::GitLab => "GitLab",
            Self::Bitbucket => "Bitbucket",
            Self::TwitterX => "Twitter/X",
            Self::LinkedIn => "LinkedIn",
            Self::Reddit => "Reddit",
            Self::Instagram => "Instagram",
            Self::Facebook => "Facebook",
            Self::Telegram => "Telegram",
            Self::Discord => "Discord",
            Self::YouTube => "YouTube",
            Self::TikTok => "TikTok",
            Self::Snapchat => "Snapchat",
            Self::Pinterest => "Pinterest",
            Self::Tumblr => "Tumblr",
            Self::Medium => "Medium",
            Self::DevTo => "Dev.to",
            Self::HackerNews => "Hacker News",
            Self::StackOverflow => "Stack Overflow",
            Self::StackExchange => "Stack Exchange",
            Self::Keybase => "Keybase",
            Self::Mastodon => "Mastodon",
            Self::Bluesky => "Bluesky",
            Self::Threads => "Threads",
            Self::WhatsApp => "WhatsApp",
            Self::Signal => "Signal",
            Self::WeChat => "WeChat",
            Self::QQ => "QQ",
            Self::VK => "VK",
            Self::Odnoklassniki => "Odnoklassniki",
            Self::TelegramChannel => "Telegram Channel",
            Self::DiscordServer => "Discord Server",
            Self::Slack => "Slack",
            Self::Matrix => "Matrix",
            Self::Element => "Element",
            Self::RocketChat => "Rocket.Chat",
            Self::Twitch => "Twitch",
            Self::Kick => "Kick",
            Self::Rumble => "Rumble",
            Self::Odysee => "Odysee",
            Self::Dailymotion => "Dailymotion",
            Self::Vimeo => "Vimeo",
            Self::Flickr => "Flickr",
            Self::VSCO => "VSCO",
            Self::Behance => "Behance",
            Self::Dribbble => "Dribbble",
            Self::CodePen => "CodePen",
            Self::Replit => "Replit",
            Self::Glitch => "Glitch",
            Self::Giters => "Giters",
            Self::SourceForge => "SourceForge",
            Self::HuggingFace => "Hugging Face",
            Self::DockerHub => "Docker Hub",
            Self::PyPI => "PyPI",
            Self::CratesIO => "crates.io",
            Self::Rubygems => "RubyGems",
            Self::NpmJS => "npm",
            Self::NuGet => "NuGet",
            Self::Packagist => "Packagist",
            Self::WordPress => "WordPress",
            Self::Blogger => "Blogger",
            Self::Gravatar => "Gravatar",
            Self::AboutMe => "About.me",
            Self::LinkTree => "Linktree",
            Self::BioLink => "Bio.link",
            Self::Carrd => "Carrd",
            Self::Hashnode => "Hashnode",
            Self::Substack => "Substack",
            Self::Ghost => "Ghost",
            Self::Patreon => "Patreon",
            Self::KoFi => "Ko-fi",
            Self::BuyMeACoffee => "Buy Me a Coffee",
            Self::OpenCollective => "Open Collective",
            Self::GoFundMe => "GoFundMe",
            Self::Kickstarter => "Kickstarter",
            Self::Indiegogo => "Indiegogo",
            Self::ProductHunt => "Product Hunt",
            Self::AngelList => "AngelList",
            Self::Crunchbase => "Crunchbase",
            Self::Bloomberg => "Bloomberg",
            Self::Forbes => "Forbes",
            Self::DuckDuckGo => "DuckDuckGo",
            Self::Custom(name) => name.as_str(),
        }
    }

    pub fn profile_url(&self, username: &str) -> Option<String> {
        let url = match self {
            Self::GitHub => format!("https://github.com/{}", username),
            Self::GitLab => format!("https://gitlab.com/{}", username),
            Self::Bitbucket => format!("https://bitbucket.org/{}/", username),
            Self::TwitterX => format!("https://x.com/{}", username),
            Self::LinkedIn => format!("https://linkedin.com/in/{}", username),
            Self::Reddit => format!("https://reddit.com/user/{}", username),
            Self::Instagram => format!("https://instagram.com/{}", username),
            Self::Facebook => format!("https://facebook.com/{}", username),
            Self::Telegram => format!("https://t.me/{}", username),
            Self::Discord => return None,
            Self::YouTube => format!("https://youtube.com/@{}", username),
            Self::TikTok => format!("https://tiktok.com/@{}", username),
            Self::Snapchat => format!("https://snapchat.com/add/{}", username),
            Self::Pinterest => format!("https://pinterest.com/{}/", username),
            Self::Tumblr => format!("https://{}.tumblr.com", username),
            Self::Medium => format!("https://medium.com/@{}", username),
            Self::DevTo => format!("https://dev.to/{}", username),
            Self::HackerNews => format!("https://news.ycombinator.com/user?id={}", username),
            Self::StackOverflow => return None,
            Self::StackExchange => return None,
            Self::Keybase => format!("https://keybase.io/{}", username),
            Self::Mastodon => return None,
            Self::Bluesky => format!("https://bsky.app/profile/{}", username),
            Self::Threads => format!("https://threads.net/@{}", username),
            Self::WhatsApp => return None,
            Self::Signal => return None,
            Self::WeChat => return None,
            Self::QQ => return None,
            Self::VK => format!("https://vk.com/{}", username),
            Self::Odnoklassniki => format!("https://ok.ru/{}", username),
            Self::TelegramChannel => format!("https://t.me/{}", username),
            Self::DiscordServer => return None,
            Self::Slack => return None,
            Self::Matrix => return None,
            Self::Element => return None,
            Self::RocketChat => return None,
            Self::Twitch => format!("https://twitch.tv/{}", username),
            Self::Kick => format!("https://kick.com/{}", username),
            Self::Rumble => format!("https://rumble.com/user/{}", username),
            Self::Odysee => format!("https://odysee.com/@{}", username),
            Self::Dailymotion => format!("https://dailymotion.com/{}", username),
            Self::Vimeo => format!("https://vimeo.com/{}", username),
            Self::Flickr => format!("https://flickr.com/people/{}/", username),
            Self::VSCO => format!("https://vsco.co/{}", username),
            Self::Behance => format!("https://behance.net/{}", username),
            Self::Dribbble => format!("https://dribbble.com/{}", username),
            Self::CodePen => format!("https://codepen.io/{}", username),
            Self::Replit => format!("https://replit.com/@{}", username),
            Self::Glitch => format!("https://glitch.com/@{}", username),
            Self::Giters => format!("https://giters.com/{}", username),
            Self::SourceForge => format!("https://sourceforge.net/u/{}/", username),
            Self::HuggingFace => format!("https://huggingface.co/{}", username),
            Self::DockerHub => format!("https://hub.docker.com/u/{}/", username),
            Self::PyPI => format!("https://pypi.org/user/{}/", username),
            Self::CratesIO => format!("https://crates.io/users/{}", username),
            Self::Rubygems => format!("https://rubygems.org/profiles/{}", username),
            Self::NpmJS => format!("https://www.npmjs.com/~{}", username),
            Self::NuGet => format!("https://www.nuget.org/profiles/{}", username),
            Self::Packagist => format!("https://packagist.org/packages/{}", username),
            Self::WordPress => format!("https://{}.wordpress.com", username),
            Self::Blogger => format!("https://{}.blogspot.com", username),
            Self::Gravatar => format!("https://gravatar.com/{}", username),
            Self::AboutMe => format!("https://about.me/{}", username),
            Self::LinkTree => format!("https://linktr.ee/{}", username),
            Self::BioLink => format!("https://bio.link/{}", username),
            Self::Carrd => format!("https://{}.carrd.co", username),
            Self::Hashnode => format!("https://hashnode.com/@{}", username),
            Self::Substack => format!("https://{}.substack.com", username),
            Self::Ghost => format!("https://{}.ghost.io", username),
            Self::Patreon => format!("https://patreon.com/{}", username),
            Self::KoFi => format!("https://ko-fi.com/{}", username),
            Self::BuyMeACoffee => format!("https://buymeacoffee.com/{}", username),
            Self::OpenCollective => format!("https://opencollective.com/{}", username),
            Self::GoFundMe => format!("https://gofundme.com/f/{}", username),
            Self::Kickstarter => format!("https://kickstarter.com/profile/{}", username),
            Self::Indiegogo => format!("https://indiegogo.com/individuals/{}", username),
            Self::ProductHunt => format!("https://producthunt.com/@{}", username),
            Self::AngelList => format!("https://angel.co/u/{}", username),
            Self::Crunchbase => format!("https://crunchbase.com/person/{}", username),
            Self::Bloomberg => return None,
            Self::Forbes => return None,
            Self::DuckDuckGo => return None,
            Self::Custom(_) => return None,
        };
        Some(url)
    }

    pub fn all() -> Vec<Platform> {
        vec![
            Self::GitHub, Self::GitLab, Self::Bitbucket,
            Self::TwitterX, Self::LinkedIn, Self::Reddit,
            Self::Instagram, Self::Facebook, Self::Telegram,
            Self::Discord, Self::YouTube, Self::TikTok,
            Self::Snapchat, Self::Pinterest, Self::Tumblr,
            Self::Medium, Self::DevTo, Self::HackerNews,
            Self::StackOverflow, Self::Keybase, Self::Mastodon,
            Self::Bluesky, Self::Threads, Self::VK,
            Self::Odnoklassniki, Self::Twitch, Self::Kick,
            Self::Rumble, Self::Odysee, Self::Dailymotion,
            Self::Vimeo, Self::Flickr, Self::VSCO,
            Self::Behance, Self::Dribbble, Self::CodePen,
            Self::Replit, Self::Glitch, Self::Giters,
            Self::SourceForge, Self::HuggingFace, Self::DockerHub,
            Self::PyPI, Self::CratesIO, Self::Rubygems,
            Self::NpmJS, Self::NuGet, Self::Packagist,
            Self::WordPress, Self::Blogger, Self::Gravatar,
            Self::AboutMe, Self::LinkTree, Self::BioLink,
            Self::Carrd, Self::Hashnode, Self::Substack,
            Self::Ghost, Self::Patreon, Self::KoFi,
            Self::BuyMeACoffee, Self::OpenCollective, Self::GoFundMe,
            Self::Kickstarter, Self::Indiegogo, Self::ProductHunt,
            Self::AngelList, Self::Crunchbase,
        ]
    }
}

#[derive(Debug, Clone)]
pub struct SocialSearcher;

impl SocialSearcher {
    pub fn search_username(username: &str, platforms: &[Platform]) -> Vec<OsintFinding> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()
            .ok();

        let mut findings = Vec::new();
        for platform in platforms {
            if let Some(url) = platform.profile_url(username) {
                let exists = client.as_ref().map_or(false, |c| {
                    check_profile_exists(c, &url)
                });
                findings.push(OsintFinding {
                    source: OsintSource {
                        name: format!("social/{}", platform.as_str()),
                        reliability: Reliability::Medium,
                        url: Some(url.clone()),
                    },
                    kind: FindingKind::SocialProfile,
                    value: format!("{} profile: {}", platform.as_str(), username),
                    context: if exists {
                        Some(format!("Profile exists at {}", url))
                    } else {
                        Some(format!("No profile found at {}", url))
                    },
                    confidence: if exists { 0.8 } else { 0.3 },
                    timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                });
            }
        }
        findings
    }
}

fn check_profile_exists(client: &reqwest::blocking::Client, url: &str) -> bool {
    match client.head(url).send() {
        Ok(resp) => {
            let status = resp.status();
            status.is_success() || status == reqwest::StatusCode::MOVED_PERMANENTLY
        }
        Err(_) => false,
    }
}

#[derive(Debug, Clone)]
pub struct ProfileExtractor;

impl ProfileExtractor {
    pub fn extract_profile(platform: &Platform, username: &str) -> Result<OsintFinding, String> {
        let url = platform.profile_url(username).ok_or_else(|| {
            format!("{} does not support URL-based profile lookup", platform.as_str())
        })?;

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()
            .map_err(|e| format!("http client: {e}"))?;

        let resp = client
            .get(&url)
            .send()
            .map_err(|e| format!("request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("profile not found (HTTP {})", resp.status()));
        }

        let html = resp.text().map_err(|e| format!("read response: {e}"))?;
        let document = scraper::Html::parse_document(&html);
        let mut context_parts: Vec<String> = Vec::new();

        if let Ok(selector) = scraper::Selector::parse("title") {
            if let Some(title) = document.select(&selector).next() {
                let text = title.text().collect::<String>().trim().to_string();
                if !text.is_empty() {
                    context_parts.push(format!("title: {}", text));
                }
            }
        }

        if let Ok(selector) = scraper::Selector::parse("meta[name=description]") {
            if let Some(meta) = document.select(&selector).next() {
                if let Some(desc) = meta.value().attr("content") {
                    let desc = desc.trim();
                    if !desc.is_empty() {
                        context_parts.push(format!("description: {}", desc));
                    }
                }
            }
        }

        if let Ok(selector) = scraper::Selector::parse("meta[property=og\\:description]") {
            if let Some(meta) = document.select(&selector).next() {
                if let Some(desc) = meta.value().attr("content") {
                    let desc = desc.trim();
                    if !desc.is_empty() {
                        context_parts.push(format!("og:description: {}", desc));
                    }
                }
            }
        }

        Ok(OsintFinding {
            source: OsintSource {
                name: format!("profile/{}", platform.as_str()),
                reliability: Reliability::Medium,
                url: Some(url),
            },
            kind: FindingKind::SocialProfile,
            value: format!("{} profile: {}", platform.as_str(), username),
            context: if context_parts.is_empty() {
                None
            } else {
                Some(context_parts.join(" | "))
            },
            confidence: 0.85,
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_profile_url() {
        let url = Platform::GitHub.profile_url("testuser").unwrap();
        assert_eq!(url, "https://github.com/testuser");
    }

    #[test]
    fn twitter_profile_url() {
        let url = Platform::TwitterX.profile_url("user").unwrap();
        assert_eq!(url, "https://x.com/user");
    }

    #[test]
    fn discord_returns_none() {
        assert!(Platform::Discord.profile_url("user").is_none());
    }

    #[test]
    fn all_platforms_have_urls_or_explicit_none() {
        for p in Platform::all() {
            let url = p.profile_url("test");
            if matches!(p, Platform::Discord | Platform::StackOverflow | Platform::StackExchange
                | Platform::WhatsApp | Platform::Signal | Platform::WeChat | Platform::QQ
                | Platform::DiscordServer | Platform::Slack | Platform::Matrix | Platform::Element
                | Platform::RocketChat | Platform::Bloomberg | Platform::Forbes
                | Platform::DuckDuckGo | Platform::Mastodon) {
                assert!(url.is_none(), "expected none for {:?}", p);
            } else {
                assert!(url.is_some(), "expected url for {:?}", p);
            }
        }
    }

    #[test]
    fn platform_as_str_returns_non_empty() {
        for p in Platform::all() {
            let name = p.as_str();
            assert!(!name.is_empty(), "empty name for {:?}", p);
        }
    }

    #[test]
    fn custom_platform_uses_name() {
        let p = Platform::Custom("TestPlatform".into());
        assert_eq!(p.as_str(), "TestPlatform");
        assert!(p.profile_url("user").is_none());
    }
}
