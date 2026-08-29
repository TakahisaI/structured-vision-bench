import { publishSuiteRunDirectory, type SuiteRunPublicationCheckpoint } from "../../src/suite/run-directory.js";
import { syntheticSuiteRunManifest } from "./synthetic-suite-run.js";

const [rootDirectory, crashPoint] = process.argv.slice(2);
if (rootDirectory === undefined || crashPoint === undefined) process.exit(64);

await publishSuiteRunDirectory(rootDirectory, syntheticSuiteRunManifest(), {
  checkpoint: (point) => {
    if (point === (crashPoint as SuiteRunPublicationCheckpoint)) process.exit(77);
  },
});
process.exit(0);
