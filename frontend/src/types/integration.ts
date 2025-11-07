export interface JiraConfig {
  url: string;
  email: string;
  api_token: string;
  project_key: string;
}

export interface SlackConfig {
  webhook_url: string;
  channel: string;
}