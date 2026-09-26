#!/usr/bin/env node
import { main } from './cli-core.ts';

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    console.error('provenance-gate: unexpected error');
    console.error(err);
    process.exitCode = 2;
  });
