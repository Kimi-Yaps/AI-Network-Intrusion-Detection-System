export type NavSectionId =
  | 'dashboard'
  | 'alerts'
  | 'dns'
  | 'monitoring'
  | 'rules'
  | 'ai_analyst'
  | 'hf_bucket'
  | 'configure'
  | 'system';

export interface ServerConfig {
  config_path?: string;
  using_system_etc_config?: boolean;
  server: {
    name: string;
    environment: string;
    listen_interface: string;
    public_ip: string;
    os?: string;
  };
  web?: {
    react_app_url: string;
    api_url: string;
    allowed_origins: string[];
  };
  monitoring: {
    suricata_eve_path: string;
    zeek_log_dir: string;
    poll_interval_seconds: number;
  };
  dns_anomaly: {
    max_queries_per_client_per_minute: number;
    max_nxdomain_ratio: number;
    high_entropy_threshold: number;
    suspicious_tlds: string[];
  };
  alerts: {
    email_to: string[];
    webhook_configured?: boolean;
    webhook_url?: string;
  };
  dataset_bucket?: {
    provider: string;
    bucket_uri: string;
    hf_dataset_id: string;
    split: string;
    streaming: boolean;
  };
}

export interface ServerStatus {
  server_name: string;
  environment?: string;
  public_ip?: string;
  interface: string;
  config_path?: string;
  suricata_log_exists: boolean;
  zeek_dns_log_exists?: boolean;
  active_alerts: number;
  tracked_dns_clients: number;
  client_query_rates?: Record<string, number>;
  recent_dns_queries?: Array<{
    id: string;
    timestamp: string;
    source_ip: string;
    rrname: string;
    rrtype: string;
    rcode: number;
    entropy: number;
    qpm_for_client: number;
  }>;
  metrics?: {
    dns_queries_per_min: number;
    nxdomain_last_5m: number;
    max_entropy_bits: number;
  };
}

export interface AnomalyAlert {
  id: string;
  timestamp: string;
  severity: 'high' | 'medium' | 'low';
  category: string;
  source_ip: string;
  summary: string;
  evidence: Record<string, unknown>;
}

export interface LangChainDatasetPayload {
  bucket_uri: string;
  endpoint?: string;
  provider: string;
  hf_dataset_id: string;
  source?: 'hf-s3-bucket' | 'hf-datasets-server' | 'fallback';
  error?: string | null;
  document_count: number;
  documents: Array<{
    page_content: string;
    metadata: Record<string, unknown>;
  }>;
}

export interface KpiCardProps {
  label: string;
  value: string;
  trendValue: string;
  trendDirection: 'up' | 'down';
  trendLabel: string;
  color: 'blue' | 'yellow' | 'orange' | 'green';
  iconSymbol: string;
  onActionClick?: () => void;
}

export interface EntityRowItem {
  id: string;
  initials: string;
  badgeColor: string;
  primaryText: string;
  secondaryText: string;
  metricText: string;
  onClick?: () => void;
}

