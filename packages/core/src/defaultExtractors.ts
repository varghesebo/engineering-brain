import { codeExtractors } from "./codeExtractor.js";
import type { Extractor } from "./extractor.js";
import { entityExtractors } from "./features/entityExtractor.js";
import { inventoryExtractor } from "./inventory.js";

/** The extractor set a default `engbrain index` runs: file inventory plus one code extractor per grammar and the feature-entity detector. */
export const DEFAULT_EXTRACTORS: readonly Extractor[] = [inventoryExtractor, ...codeExtractors, ...entityExtractors];
