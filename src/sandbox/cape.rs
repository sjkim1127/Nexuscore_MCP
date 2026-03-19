use anyhow::{bail, Context, Result};
use reqwest::{multipart, Client};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;

#[derive(Clone)]
pub struct CapeClient {
    base_url: String,
    #[allow(dead_code)]
    api_token: String, // CAPE setting optional
    client: Client,
}

impl CapeClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token: token.to_string(),
            client: Client::new(),
        }
    }

    /// 1. Submit malware file
    pub async fn submit_file(&self, file_path: &str, machine: Option<&str>) -> Result<u64> {
        let path = Path::new(file_path);
        let filename = path
            .file_name()
            .context("Invalid filename")?
            .to_string_lossy()
            .into_owned();

        let content = fs::read(path)
            .await
            .context(format!("Failed to read file: {}", file_path))?;

        // Multipart Form
        let part = multipart::Part::bytes(content).file_name(filename);
        let mut form = multipart::Form::new().part("file", part);

        // Specific VM (e.g. "cuckoo1")
        if let Some(m) = machine {
            form = form.text("machine", m.to_string());
        }

        // CAPEv2 API Call
        let url = format!("{}/tasks/create/file/", self.base_url);
        let mut request = self.client.post(&url);
        if !self.api_token.is_empty() {
            request = request.header("Authorization", format!("Token {}", self.api_token));
        }
        let resp = request
            .multipart(form)
            .send()
            .await
            .context("Failed to connect to CAPE server")?;

        if !resp.status().is_success() {
            let err_text = resp.text().await?;
            bail!("CAPE submission failed: {}", err_text);
        }

        // Extract Task ID
        let json: Value = resp.json().await?;
        let task_id = json["task_id"].as_u64().context("No task_id in response")?;

        Ok(task_id)
    }

    /// 2. Wait for analysis (Polling)
    pub async fn wait_for_analysis(&self, task_id: u64, timeout_secs: u64) -> Result<String> {
        let url = format!("{}/tasks/view/{}/", self.base_url, task_id);
        let start = std::time::Instant::now();

        loop {
            if start.elapsed().as_secs() > timeout_secs {
                bail!("Analysis timeout detected!");
            }

            let resp = self.client.get(&url).send().await?;
            if resp.status().is_success() {
                let json: Value = resp.json().await?;
                // Status path might vary by CAPE version, usually task.status
                let status = json["task"]["status"].as_str().unwrap_or("unknown");

                match status {
                    "reported" => return Ok("reported".to_string()),
                    "failed_analysis" => bail!("Analysis failed inside CAPE"),
                    _ => {
                        // pending, running, completed, processing...
                        sleep(Duration::from_secs(5)).await; // Wait 5s
                        continue;
                    }
                }
            }
            sleep(Duration::from_secs(5)).await;
        }
    }

    /// 3. Get Report
    pub async fn get_report(&self, task_id: u64) -> Result<Value> {
        let url = format!("{}/tasks/report/{}/", self.base_url, task_id);
        let resp = self.client.get(&url).send().await?;

        let report: Value = resp.json().await?;
        Ok(report)
    }
}
