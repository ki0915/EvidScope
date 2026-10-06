import { lstat } from 'node:fs/promises';
import { resolve } from 'node:path';

// This is a scheduling boundary, not proof that the GPU is idle or an OS lock.
// An unfinished or malformed owned-job lease must never be deleted by tests.
export async function assertCpuVerificationCanStart(repositoryRoot) {
  const lease = resolve(repositoryRoot, '.local/training/manual-public-qa-active.json');
  try {
    await lstat(lease);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw Error('Memory scheduling check unavailable; verification not started', { cause: error });
  }
  throw Error('Active or unconfirmed public-QA job lease; finish and verify GPU cleanup before CPU release verification');
}
