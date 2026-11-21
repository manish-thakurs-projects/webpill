import mongoose, { Schema } from 'mongoose';
import type { AnalysisResponse } from '@webpill/shared';

export interface CachedDomainAnalysis {
  cacheKey: string;
  domain: string;
  result: AnalysisResponse;
  createdAt: Date;
  expiresAt: Date;
}

const domainAnalysisSchema = new Schema<CachedDomainAnalysis>({
  cacheKey: { type: String, required: true, unique: true },
  domain: { type: String, required: true, index: true },
  result: { type: Schema.Types.Mixed, required: true },
  createdAt: { type: Date, required: true, default: Date.now, index: true },
  expiresAt: { type: Date, required: true },
}, { versionKey: false });

domainAnalysisSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
domainAnalysisSchema.index({ domain: 1, createdAt: -1 });

export const DomainAnalysisModel = mongoose.models.DomainAnalysis
  ?? mongoose.model<CachedDomainAnalysis>('DomainAnalysis', domainAnalysisSchema);
