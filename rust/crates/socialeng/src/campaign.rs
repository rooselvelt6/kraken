

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CampaignStats {
    pub name: String,
    pub total_sent: usize,
    pub total_opened: usize,
    pub total_clicked: usize,
    pub total_creds: usize,
    pub open_rate: f64,
    pub click_rate: f64,
    pub cred_rate: f64,
    pub targets: Vec<String>,
    pub opened: Vec<String>,
    pub clicked: Vec<String>,
    pub submitted: Vec<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CampaignEvent {
    pub timestamp: String,
    pub target: String,
    pub event_type: String,
    pub detail: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CampaignTracker {
    pub name: String,
    pub events: Vec<CampaignEvent>,
}

impl CampaignTracker {
    pub fn new(name: &str) -> Self {
        CampaignTracker {
            name: name.to_string(),
            events: Vec::new(),
        }
    }

    pub fn track_sent(&mut self, target: &str) {
        self.events.push(CampaignEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            target: target.to_string(),
            event_type: "sent".to_string(),
            detail: "Email sent".to_string(),
            ip: None,
            user_agent: None,
        });
    }

    pub fn track_open(&mut self, target: &str, ip: &str, user_agent: &str) {
        self.events.push(CampaignEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            target: target.to_string(),
            event_type: "opened".to_string(),
            detail: "Email opened / pixel loaded".to_string(),
            ip: Some(ip.to_string()),
            user_agent: Some(user_agent.to_string()),
        });
    }

    pub fn track_click(&mut self, target: &str, link: &str, ip: &str, user_agent: &str) {
        self.events.push(CampaignEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            target: target.to_string(),
            event_type: "clicked".to_string(),
            detail: format!("Clicked link: {}", link),
            ip: Some(ip.to_string()),
            user_agent: Some(user_agent.to_string()),
        });
    }

    pub fn track_credential(&mut self, target: &str, field_summary: &str, ip: &str, user_agent: &str) {
        self.events.push(CampaignEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            target: target.to_string(),
            event_type: "submitted".to_string(),
            detail: format!("Credentials captured: {}", field_summary),
            ip: Some(ip.to_string()),
            user_agent: Some(user_agent.to_string()),
        });
    }

    pub fn get_events(&self) -> &[CampaignEvent] {
        &self.events
    }

    pub fn get_stats(&self) -> CampaignStats {
        let targets: Vec<String> = self.events.iter()
            .map(|e| e.target.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let total_sent = targets.len();
        let opened_targets: std::collections::HashSet<String> = self.events.iter()
            .filter(|e| e.event_type == "opened")
            .map(|e| e.target.clone())
            .collect();
        let total_opened = opened_targets.len();

        let clicked_targets: std::collections::HashSet<String> = self.events.iter()
            .filter(|e| e.event_type == "clicked")
            .map(|e| e.target.clone())
            .collect();
        let total_clicked = clicked_targets.len();

        let submitted_targets: std::collections::HashSet<String> = self.events.iter()
            .filter(|e| e.event_type == "submitted")
            .map(|e| e.target.clone())
            .collect();
        let total_creds = submitted_targets.len();

        let start_time = self.events.first().map(|e| e.timestamp.clone());
        let end_time = self.events.last().map(|e| e.timestamp.clone());

        let open_rate = if total_sent > 0 { total_opened as f64 / total_sent as f64 * 100.0 } else { 0.0 };
        let click_rate = if total_sent > 0 { total_clicked as f64 / total_sent as f64 * 100.0 } else { 0.0 };
        let cred_rate = if total_sent > 0 { total_creds as f64 / total_sent as f64 * 100.0 } else { 0.0 };

        CampaignStats {
            name: self.name.clone(),
            total_sent,
            total_opened,
            total_clicked,
            total_creds,
            open_rate,
            click_rate,
            cred_rate,
            targets: targets.clone(),
            opened: opened_targets.into_iter().collect(),
            clicked: clicked_targets.into_iter().collect(),
            submitted: submitted_targets.into_iter().collect(),
            start_time,
            end_time,
        }
    }

    pub fn export_csv(&self) -> String {
        let mut csv = String::from("timestamp,target,event_type,detail,ip,user_agent\n");
        for event in &self.events {
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                event.timestamp,
                event.target,
                event.event_type,
                event.detail.replace('"', "\"\""),
                event.ip.as_deref().unwrap_or(""),
                event.user_agent.as_deref().unwrap_or(""),
            ));
        }
        csv
    }

    pub fn generate_tracking_pixel(tracker_url: &str, campaign_id: &str, target: &str) -> String {
        let encoded_target = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, target.as_bytes());
        format!(
            r#"<img src="{}/track/{}/{}/pixel.png" width="1" height="1" style="display:none" />"#,
            tracker_url.trim_end_matches('/'),
            campaign_id,
            encoded_target
        )
    }

    pub fn generate_tracking_link(tracker_url: &str, campaign_id: &str, target: &str, real_url: &str) -> String {
        let encoded_target = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, target.as_bytes());
        let encoded_url = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, real_url.as_bytes());
        format!(
            "{}/click/{}/{}/{}",
            tracker_url.trim_end_matches('/'),
            campaign_id,
            encoded_target,
            encoded_url
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_track_sent() {
        let mut tracker = CampaignTracker::new("Campaign 1");
        tracker.track_sent("victim@test.com");
        assert_eq!(tracker.get_events().len(), 1);
        assert_eq!(tracker.get_events()[0].event_type, "sent");
    }

    #[test]
    fn test_track_open() {
        let mut tracker = CampaignTracker::new("Test");
        tracker.track_open("user@test.com", "10.0.0.1", "Mozilla/5.0");
        assert_eq!(tracker.get_events()[0].event_type, "opened");
        assert_eq!(tracker.get_events()[0].ip.as_deref().unwrap(), "10.0.0.1");
    }

    #[test]
    fn test_track_click() {
        let mut tracker = CampaignTracker::new("Test");
        tracker.track_click("user@test.com", "http://evil.com", "10.0.0.1", "Mozilla");
        assert_eq!(tracker.get_events()[0].event_type, "clicked");
    }

    #[test]
    fn test_track_credential() {
        let mut tracker = CampaignTracker::new("Test");
        tracker.track_credential("user@test.com", "email,password", "10.0.0.1", "Mozilla");
        assert_eq!(tracker.get_events()[0].event_type, "submitted");
    }

    #[test]
    fn test_get_stats() {
        let mut tracker = CampaignTracker::new("Test Campaign");
        tracker.track_sent("a@b.com");
        tracker.track_sent("c@d.com");
        tracker.track_open("a@b.com", "1.2.3.4", "UA");
        tracker.track_click("a@b.com", "http://evil.com", "1.2.3.4", "UA");
        tracker.track_credential("a@b.com", "user,pass", "1.2.3.4", "UA");

        let stats = tracker.get_stats();
        assert_eq!(stats.total_sent, 2);
        assert_eq!(stats.total_opened, 1);
        assert_eq!(stats.total_clicked, 1);
        assert_eq!(stats.total_creds, 1);
        assert!((stats.open_rate - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_export_csv() {
        let mut tracker = CampaignTracker::new("Test");
        tracker.track_sent("user@test.com");
        let csv = tracker.export_csv();
        assert!(csv.contains("user@test.com"));
    }

    #[test]
    fn test_generate_tracking_pixel() {
        let pixel = CampaignTracker::generate_tracking_pixel("http://tracker.com", "camp1", "victim@test.com");
        assert!(pixel.contains("tracker.com/track/"));
        assert!(pixel.contains("pixel.png"));
    }

    #[test]
    fn test_generate_tracking_link() {
        let link = CampaignTracker::generate_tracking_link("http://tracker.com", "camp1", "user@test.com", "http://evil.com");
        assert!(link.contains("/click/"));
    }

    #[test]
    fn test_empty_stats() {
        let tracker = CampaignTracker::new("Empty");
        let stats = tracker.get_stats();
        assert_eq!(stats.total_sent, 0);
        assert_eq!(stats.total_opened, 0);
    }

    #[test]
    fn test_campaign_stats() {
        let stats = CampaignStats {
            name: "Test".to_string(),
            total_sent: 100,
            total_opened: 45,
            total_clicked: 12,
            total_creds: 5,
            open_rate: 45.0,
            click_rate: 12.0,
            cred_rate: 5.0,
            targets: vec![],
            opened: vec![],
            clicked: vec![],
            submitted: vec![],
            start_time: None,
            end_time: None,
        };
        let json = serde_json::to_string_pretty(&stats).unwrap();
        assert!(json.contains("\"open_rate\": 45.0"));
    }
}
