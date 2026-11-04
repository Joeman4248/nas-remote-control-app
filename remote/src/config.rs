//! buttons.toml: the remote's button list.

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    #[serde(rename = "button")]
    pub buttons: Vec<Button>,
}

#[derive(Deserialize)]
pub struct Button {
    pub screen: String,
    pub label: String,
    #[serde(default = "default_style")]
    pub style: String,
    pub when: Option<String>,
    #[serde(default)]
    pub confirm: Vec<String>,
    pub yes: Option<String>,
    #[serde(default)]
    pub run: Vec<String>,
    pub wait: Option<String>,
    pub show: Option<String>,
    pub done: Option<String>,
    pub does: Option<String>,
}

fn default_style() -> String {
    "BTN".into()
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let cfg: Config = toml::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
        for b in &cfg.buttons {
            if b.run.is_empty() == b.does.is_none() {
                return Err(format!("{path}: button {:?} needs exactly one of run or does", b.label));
            }
        }
        Ok(cfg)
    }

    /// (index, button) on one screen, in file order.
    pub fn on(&self, screen: &str) -> impl Iterator<Item = (usize, &Button)> {
        self.buttons
            .iter()
            .enumerate()
            .filter(move |(_, b)| b.screen == screen)
    }
}

/// Replace {key} placeholders.
pub fn fill(text: &str, vars: &[(&str, &str)]) -> String {
    vars.iter().fold(text.to_string(), |t, (k, v)| t.replace(&format!("{{{k}}}"), v))
}
