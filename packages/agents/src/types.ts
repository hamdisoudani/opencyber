export interface GovernedRequestOptions {
  method?: 'GET' | 'HEAD' | 'OPTIONS';
  headers?: Record<string, string>;
  authProfile?: string;
}

export interface GovernedResponse {
  status: number;
  headers: Record<string, string>;
  bodyText: string;
  harSha256?: string;
}

export interface HttpFetcher {
  request(targetUrl: string, opts?: GovernedRequestOptions): Promise<GovernedResponse>;
}
