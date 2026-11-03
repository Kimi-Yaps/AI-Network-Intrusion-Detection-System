/**
 * Hugging Face S3-compatible bucket access (s3.hf.co) + LangChain Document conversion.
 *
 * Credentials are read from the environment only (never logged):
 *   - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY  (preferred, as in the HF S3 example)
 *   - HUGGINGFACE_API_KEY                        (fallback for both values)
 *
 * Optional overrides:
 *   HF_S3_ENDPOINT (default https://s3.hf.co/kimi-yaps)
 *   HF_S3_BUCKET   (default MyBucket)
 *   HF_S3_KEY      (default example.txt)
 *   HF_S3_PREFIX   (default "", used when listing objects)
 *   HF_S3_REGION   (default us-east-1)
 */
import {
  GetObjectCommand,
  ListObjectsV2Command,
  S3Client,
} from '@aws-sdk/client-s3';
import { FetchHttpHandler } from '@smithy/fetch-http-handler';
import { Document } from '@langchain/core/documents';

export interface HfBucketSettings {
  endpoint: string;
  bucket: string;
  key: string;
  prefix: string;
  region: string;
}

export interface HfBucketLoadResult {
  documents: Document[];
  key: string;
  settings: HfBucketSettings;
}

export function getHfBucketSettings(): HfBucketSettings {
  return {
    endpoint: process.env.HF_S3_ENDPOINT || 'https://s3.hf.co/kimi-yaps',
    bucket: process.env.HF_S3_BUCKET || 'MyBucket',
    key: process.env.HF_S3_KEY || 'example.txt',
    prefix: process.env.HF_S3_PREFIX || '',
    region: process.env.HF_S3_REGION || 'us-east-1',
  };
}

export function hasHfBucketCredentials(): boolean {
  return Boolean(
    (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) ||
      process.env.HUGGINGFACE_API_KEY
  );
}

let cachedClient: S3Client | null = null;

function getClient(settings: HfBucketSettings): S3Client {
  if (cachedClient) return cachedClient;

  const accessKeyId = process.env.AWS_ACCESS_KEY_ID || process.env.HUGGINGFACE_API_KEY;
  const secretAccessKey =
    process.env.AWS_SECRET_ACCESS_KEY || process.env.HUGGINGFACE_API_KEY;

  if (!accessKeyId || !secretAccessKey) {
    throw new Error(
      'Missing bucket credentials: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or HUGGINGFACE_API_KEY in .env'
    );
  }

  cachedClient = new S3Client({
    requestHandler: new FetchHttpHandler(),
    endpoint: settings.endpoint,
    region: settings.region,
    forcePathStyle: true,
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
    credentials: { accessKeyId, secretAccessKey },
  });
  return cachedClient;
}

/** Lists object keys in the bucket (optionally under HF_S3_PREFIX). */
export async function listHfBucketObjects(limit = 50): Promise<string[]> {
  const settings = getHfBucketSettings();
  const res = await getClient(settings).send(
    new ListObjectsV2Command({
      Bucket: settings.bucket,
      Prefix: settings.prefix || undefined,
      MaxKeys: limit,
    })
  );
  return (res.Contents ?? [])
    .map((obj) => obj.Key)
    .filter((k): k is string => Boolean(k));
}

/** Reads a single object from the bucket as UTF-8 text. */
export async function readHfBucketObject(key?: string): Promise<string> {
  const settings = getHfBucketSettings();
  const res = await getClient(settings).send(
    new GetObjectCommand({
      Bucket: settings.bucket,
      Key: key || settings.key,
    })
  );
  if (!res.Body) return '';
  return res.Body.transformToString();
}

function chunkText(text: string, maxChars = 1200): string[] {
  const paragraphs = text.split(/\n\s*\n/).map((p) => p.trim()).filter(Boolean);
  const chunks: string[] = [];
  let current = '';
  for (const p of paragraphs) {
    if ((current + '\n\n' + p).length > maxChars && current) {
      chunks.push(current);
      current = p;
    } else {
      current = current ? `${current}\n\n${p}` : p;
    }
  }
  if (current) chunks.push(current);
  return chunks;
}

function parseCsv(text: string): Record<string, string>[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return [];
  const headers = lines[0].split(',').map((h) => h.trim());
  return lines.slice(1).map((line) => {
    const cells = line.split(',');
    return Object.fromEntries(headers.map((h, i) => [h, (cells[i] ?? '').trim()]));
  });
}

/** Converts raw object text into LangChain Documents based on file extension. */
export function textToDocuments(
  text: string,
  key: string,
  settings: HfBucketSettings,
  limit = 50
): Document[] {
  const baseMeta = {
    source: `s3://${settings.bucket}/${key}`,
    endpoint: settings.endpoint,
    bucket: settings.bucket,
    key,
  };
  const lower = key.toLowerCase();
  let records: unknown[] = [];

  try {
    if (lower.endsWith('.jsonl') || lower.endsWith('.ndjson')) {
      records = text
        .split(/\r?\n/)
        .filter((l) => l.trim())
        .map((l) => JSON.parse(l));
    } else if (lower.endsWith('.json')) {
      const parsed = JSON.parse(text);
      records = Array.isArray(parsed) ? parsed : [parsed];
    } else if (lower.endsWith('.csv')) {
      records = parseCsv(text);
    }
  } catch {
    records = [];
  }

  if (records.length > 0) {
    return records.slice(0, limit).map(
      (row, idx) =>
        new Document({
          pageContent: typeof row === 'string' ? row : JSON.stringify(row),
          metadata: { ...baseMeta, row_idx: idx },
        })
    );
  }

  return chunkText(text)
    .slice(0, limit)
    .map(
      (chunk, idx) =>
        new Document({
          pageContent: chunk,
          metadata: { ...baseMeta, chunk_idx: idx },
        })
    );
}

/** Turns opaque AWS SDK errors (e.g. "UnknownError") into readable messages. */
export function describeBucketError(err: unknown, bucket: string, key?: string): string {
  const e = err as {
    name?: string;
    message?: string;
    Code?: string;
    $metadata?: { httpStatusCode?: number };
  };
  const status = e?.$metadata?.httpStatusCode;
  const target = key ? `s3://${bucket}/${key}` : `s3://${bucket}`;
  const hints: Record<number, string> = {
    301: 'wrong endpoint/region for this bucket',
    400: 'bad request (check endpoint path and bucket name)',
    401: 'credentials rejected',
    403: 'access denied (token lacks permission for this bucket, or wrong access key/secret)',
    404: 'bucket or object key not found (check HF_S3_BUCKET / HF_S3_KEY)',
  };
  const parts = [
    e?.name && e.name !== 'UnknownError' ? e.name : e?.Code,
    status ? `HTTP ${status}` : undefined,
    status && hints[status] ? hints[status] : undefined,
    target,
  ].filter(Boolean);
  return parts.length > 1 ? parts.join(' — ') : e?.message || String(err);
}

/** Reads an object from the Hugging Face bucket and returns LangChain Documents. */
export async function loadHfBucketDocuments(
  limit = 5,
  key?: string
): Promise<HfBucketLoadResult> {
  const settings = getHfBucketSettings();
  const targetKey = key || settings.key;
  let text: string;
  try {
    text = await readHfBucketObject(targetKey);
  } catch (err) {
    throw new Error(describeBucketError(err, settings.bucket, targetKey));
  }
  return {
    documents: textToDocuments(text, targetKey, settings, limit),
    key: targetKey,
    settings,
  };
}

