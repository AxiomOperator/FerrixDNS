//! Well-known services that can be blocked by name, as a set of domains.
//!
//! The domains are what each service's apps and websites depend on. Blocking one can't be complete,
//! because services change their domains and share content networks, so these avoid shared
//! infrastructure that would break other sites.

use crate::compile::{MatchType, Rule, RuleAction, Scope};
use crate::document::BlockedServiceDef;

/// A service that can be blocked in one step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Service {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    /// Blocked along with their subdomains.
    pub domains: &'static [&'static str],
}

const fn service(
    id: &'static str,
    name: &'static str,
    category: &'static str,
    domains: &'static [&'static str],
) -> Service {
    Service {
        id,
        name,
        category,
        domains,
    }
}

const SOCIAL: &str = "Social media";
const VIDEO: &str = "Video and music";
const GAMES: &str = "Games";
const CHAT: &str = "Messaging";
const SHOPPING: &str = "Shopping";
const OTHER: &str = "Other";

/// Every service, in the order they're shown.
pub const SERVICES: &[Service] = &[
    service(
        "facebook",
        "Facebook",
        SOCIAL,
        &[
            "facebook.com",
            "fb.com",
            "fb.gg",
            "fbcdn.net",
            "fbsbx.com",
            "facebook.net",
            "messenger.com",
        ],
    ),
    service(
        "instagram",
        "Instagram",
        SOCIAL,
        &["instagram.com", "cdninstagram.com", "ig.me"],
    ),
    service(
        "threads",
        "Threads",
        SOCIAL,
        &["threads.net", "threads.com"],
    ),
    service(
        "tiktok",
        "TikTok",
        SOCIAL,
        &[
            "tiktok.com",
            "tiktokv.com",
            "tiktokcdn.com",
            "tiktokcdn-us.com",
            "tiktokv.us",
            "ttwstatic.com",
            "musical.ly",
            "byteoversea.com",
            "ibytedtos.com",
            "muscdn.com",
        ],
    ),
    service(
        "snapchat",
        "Snapchat",
        SOCIAL,
        &[
            "snapchat.com",
            "snap.com",
            "sc-cdn.net",
            "snapkit.com",
            "snapads.com",
            "feelinsonice.com",
        ],
    ),
    service(
        "x",
        "X (Twitter)",
        SOCIAL,
        &[
            "x.com",
            "twitter.com",
            "twimg.com",
            "t.co",
            "ads-twitter.com",
        ],
    ),
    service(
        "reddit",
        "Reddit",
        SOCIAL,
        &[
            "reddit.com",
            "redd.it",
            "redditmedia.com",
            "redditstatic.com",
            "redditspeedtest.com",
        ],
    ),
    service(
        "pinterest",
        "Pinterest",
        SOCIAL,
        &["pinterest.com", "pinimg.com", "pin.it"],
    ),
    service(
        "linkedin",
        "LinkedIn",
        SOCIAL,
        &["linkedin.com", "licdn.com", "lnkd.in"],
    ),
    service("tumblr", "Tumblr", SOCIAL, &["tumblr.com"]),
    service(
        "bluesky",
        "Bluesky",
        SOCIAL,
        &["bsky.app", "bsky.social", "bsky.network"],
    ),
    service(
        "mastodon",
        "Mastodon (main servers)",
        SOCIAL,
        &["mastodon.social", "joinmastodon.org", "mastodon.online"],
    ),
    service(
        "youtube",
        "YouTube",
        VIDEO,
        &[
            "youtube.com",
            "youtu.be",
            "ytimg.com",
            "googlevideo.com",
            "youtubei.googleapis.com",
            "youtube-nocookie.com",
            "youtube-ui.l.google.com",
            "yt.be",
            "ggpht.com",
        ],
    ),
    service(
        "netflix",
        "Netflix",
        VIDEO,
        &[
            "netflix.com",
            "nflxvideo.net",
            "nflximg.net",
            "nflxso.net",
            "nflxext.com",
        ],
    ),
    service(
        "twitch",
        "Twitch",
        VIDEO,
        &[
            "twitch.tv",
            "ttvnw.net",
            "jtvnw.net",
            "twitchcdn.net",
            "twitchsvc.net",
            "ext-twitch.tv",
        ],
    ),
    service(
        "disney-plus",
        "Disney+",
        VIDEO,
        &[
            "disneyplus.com",
            "disney-plus.net",
            "dssott.com",
            "bamgrid.com",
            "dssedge.com",
        ],
    ),
    service(
        "hulu",
        "Hulu",
        VIDEO,
        &["hulu.com", "hulustream.com", "huluim.com"],
    ),
    service(
        "prime-video",
        "Prime Video",
        VIDEO,
        &[
            "primevideo.com",
            "aiv-cdn.net",
            "aiv-delivery.net",
            "amazonvideo.com",
            "media-amazon.com",
        ],
    ),
    service(
        "max",
        "Max",
        VIDEO,
        &["max.com", "hbomax.com", "hbo.com", "hbomaxcdn.com"],
    ),
    service(
        "spotify",
        "Spotify",
        VIDEO,
        &[
            "spotify.com",
            "scdn.co",
            "spotifycdn.com",
            "spotify.link",
            "spotifycharts.com",
        ],
    ),
    service("vimeo", "Vimeo", VIDEO, &["vimeo.com", "vimeocdn.com"]),
    service(
        "steam",
        "Steam",
        GAMES,
        &[
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "steamcontent.com",
            "steamserver.net",
            "steamusercontent.com",
        ],
    ),
    service(
        "epic-games",
        "Epic Games and Fortnite",
        GAMES,
        &[
            "epicgames.com",
            "epicgames.dev",
            "fortnite.com",
            "unrealengine.com",
            "ol.epicgames.com",
        ],
    ),
    service(
        "roblox",
        "Roblox",
        GAMES,
        &["roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com"],
    ),
    service(
        "minecraft",
        "Minecraft",
        GAMES,
        &["minecraft.net", "mojang.com", "minecraftservices.com"],
    ),
    service(
        "xbox",
        "Xbox Live",
        GAMES,
        &["xbox.com", "xboxlive.com", "xboxservices.com"],
    ),
    service(
        "playstation",
        "PlayStation Network",
        GAMES,
        &[
            "playstation.com",
            "playstation.net",
            "sonyentertainmentnetwork.com",
        ],
    ),
    service(
        "nintendo",
        "Nintendo Online",
        GAMES,
        &["nintendo.com", "nintendo.net", "nintendo-europe.com"],
    ),
    service(
        "discord",
        "Discord",
        CHAT,
        &[
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
            "discord.media",
            "discordcdn.com",
            "discordstatus.com",
        ],
    ),
    service(
        "whatsapp",
        "WhatsApp",
        CHAT,
        &["whatsapp.com", "whatsapp.net", "wa.me"],
    ),
    service(
        "telegram",
        "Telegram",
        CHAT,
        &[
            "telegram.org",
            "telegram.me",
            "t.me",
            "tdesktop.com",
            "telesco.pe",
        ],
    ),
    service(
        "signal",
        "Signal",
        CHAT,
        &["signal.org", "whispersystems.org", "signal.me"],
    ),
    service(
        "amazon-shopping",
        "Amazon shopping",
        SHOPPING,
        &[
            "amazon.com",
            "amazon.co.uk",
            "amazon.ca",
            "amazon.de",
            "a2z.com",
            "ssl-images-amazon.com",
        ],
    ),
    service(
        "ebay",
        "eBay",
        SHOPPING,
        &["ebay.com", "ebayimg.com", "ebaystatic.com", "ebayrtm.com"],
    ),
    service("temu", "Temu", SHOPPING, &["temu.com", "kwcdn.com"]),
    service(
        "shein",
        "Shein",
        SHOPPING,
        &["shein.com", "sheincdn.com", "ltwebstatic.com"],
    ),
    service(
        "chatgpt",
        "ChatGPT",
        OTHER,
        &[
            "chatgpt.com",
            "chat.openai.com",
            "oaistatic.com",
            "oaiusercontent.com",
        ],
    ),
    service(
        "tinder",
        "Tinder",
        OTHER,
        &["tinder.com", "gotinder.com", "tindersparks.com"],
    ),
    service(
        "bittorrent",
        "BitTorrent trackers and sites",
        OTHER,
        &[
            "thepiratebay.org",
            "1337x.to",
            "rarbg.to",
            "bittorrent.com",
            "utorrent.com",
        ],
    ),
];

/// Finds a service by its ID.
pub fn find_service(id: &str) -> Option<&'static Service> {
    SERVICES.iter().find(|service| service.id == id)
}

/// The ID of the rule that blocks one of a service's domains, for one group or for everyone.
fn rule_id(service: &str, domain: &str, group: Option<&str>) -> String {
    match group {
        Some(group) => format!("service:{service}:{domain}@{group}"),
        None => format!("service:{service}:{domain}"),
    }
}

/// The IDs of the rules a blocked service stands for.
pub fn service_rule_ids(definition: &BlockedServiceDef, service: &Service) -> Vec<String> {
    expand(definition, service)
        .into_iter()
        .map(|rule| rule.id)
        .collect()
}

/// The name of the service a rule ID belongs to, if it's one of these rules.
pub fn service_of_rule(rule_id: &str) -> Option<&'static Service> {
    let (id, _) = rule_id.strip_prefix("service:")?.split_once(':')?;
    find_service(id)
}

/// The rules a blocked service stands for. They're suffix denies, so an allow rule for one name
/// still makes an exception, as it would for any other rule.
pub(crate) fn expand(definition: &BlockedServiceDef, service: &Service) -> Vec<Rule> {
    let scopes: Vec<(Scope, Option<&str>)> = if definition.groups.is_empty() {
        vec![(Scope::Global, None)]
    } else {
        definition
            .groups
            .iter()
            .map(|group| (Scope::Group(group.clone()), Some(group.as_str())))
            .collect()
    };
    let mut rules = Vec::with_capacity(service.domains.len() * scopes.len());
    for (scope, group) in &scopes {
        for domain in service.domains {
            rules.push(Rule {
                id: rule_id(service.id, domain, *group),
                action: RuleAction::Deny,
                match_type: MatchType::Suffix,
                pattern: (*domain).to_owned(),
                scope: scope.clone(),
                is_emergency: false,
                enabled: true,
                expires_at: None,
            });
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::DomainName;

    use super::*;

    #[test]
    fn the_catalog_is_valid() {
        let mut ids = HashSet::new();
        for service in SERVICES {
            assert!(ids.insert(service.id), "{} appears twice", service.id);
            assert!(
                !service.id.contains(':'),
                "{} can't be in a rule ID",
                service.id
            );
            assert!(!service.domains.is_empty(), "{}", service.id);
            for domain in service.domains {
                DomainName::parse(domain).unwrap_or_else(|_| panic!("{domain} isn't a domain"));
            }
        }
    }

    #[test]
    fn rule_ids_lead_back_to_their_service() {
        assert_eq!(
            service_of_rule("service:tiktok:tiktok.com").unwrap().name,
            "TikTok"
        );
        assert_eq!(
            service_of_rule("service:x:t.co@kids").unwrap().name,
            "X (Twitter)"
        );
        assert!(service_of_rule("01J0000000").is_none());
        assert!(service_of_rule("service:nothing:example.com").is_none());
    }
}
