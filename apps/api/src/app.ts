import cors from 'cors';
import express, { type ErrorRequestHandler } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { z } from 'zod';
import { DomainAnalysisModel } from './models/DomainAnalysis.js';
import { analyzeRequestSchema } from '@webpill/shared';
import { analyzeWebsite, findLatestDomainAnalysis } from './services/analysis.js';

const app = express();
const allowedOrigins = (process.env.FRONTEND_ORIGINS ?? 'http://localhost:5173')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
const domainSchema = z.string().min(1).max(253).regex(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/i);

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
}));
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin) || /^(chrome|moz)-extension:\/\/[a-z0-9-]+$/i.test(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error('Origin is not allowed by CORS.'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
  maxAge: 600,
}));
app.use(express.json({ limit: '16kb', strict: true }));
app.use((request, response, next) => {
  const started = Date.now();
  response.on('finish', () => {
    console.info(JSON.stringify({
      level: 'info',
      event: 'http_request',
      method: request.method,
      path: request.route?.path ?? 'unmatched',
      status: response.statusCode,
      durationMs: Date.now() - started,
    }));
  });
  next();
});
app.use(rateLimit({
  windowMs: 60_000,
  limit: 60,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again shortly.' },
}));

app.get('/api/health', (_request, response) => {
  const databaseState = ['disconnected', 'connected', 'connecting', 'disconnecting'][DomainAnalysisModel.db.readyState] ?? 'unknown';
  response.json({
    status: 'ok',
    cache: databaseState === 'connected' ? 'mongodb_and_memory' : 'memory',
    database: databaseState,
    checkedAt: new Date().toISOString(),
  });
});

app.post('/api/analyze', async (request, response, next) => {
  const parsed = analyzeRequestSchema.safeParse(request.body);
  if (!parsed.success) {
    response.status(400).json({
      error: 'Invalid analysis request.',
      details: parsed.error.issues.map(({ path, message }) => ({ path: path.join('.'), message })),
    });
    return;
  }
  try {
    response.json(await analyzeWebsite(parsed.data));
  } catch (error) {
    next(error);
  }
});

app.get('/api/domain/:domain', async (request, response, next) => {
  const parsed = domainSchema.safeParse(request.params.domain);
  if (!parsed.success) {
    response.status(400).json({ error: 'A valid domain name is required.' });
    return;
  }
  try {
    const result = await findLatestDomainAnalysis(parsed.data);
    if (!result) {
      response.status(404).json({ error: 'No cached analysis was found for this domain.' });
      return;
    }
    response.json(result);
  } catch (error) {
    next(error);
  }
});

app.use((_request, response) => response.status(404).json({ error: 'Endpoint not found.' }));

const errorHandler: ErrorRequestHandler = (error, _request, response, next) => {
  void next;
  const status = error instanceof SyntaxError ? 400 : 500;
  const message = status === 400 ? 'Malformed JSON request.' : 'The analysis service encountered an error.';
  console.error(JSON.stringify({
    level: 'error',
    event: 'request_failed',
    detail: error instanceof Error ? error.message : 'Unknown error',
    status,
  }));
  response.status(status).json({ error: message });
};
app.use(errorHandler);

export { app };
