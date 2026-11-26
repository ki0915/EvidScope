import {existsSync} from 'node:fs';

// Some research tests read unshipped, gitignored .local artifacts.
// Gate on the artifact-set root only: absent root => explicit skip; present root => the test
// runs normally, so a missing or changed file inside a present set is still a real failure.
// EVIDSCOPE_REQUIRE_RESEARCH_ARTIFACTS=1 disables the skip (research PC / pre-publication check).
export function researchArtifactsSkip(...roots){
 const missing=roots.filter(root=>!existsSync(root));
 if(!missing.length||process.env.EVIDSCOPE_REQUIRE_RESEARCH_ARTIFACTS==='1')return false;
 return `unshipped research artifacts absent (${missing.join(', ')}); set EVIDSCOPE_REQUIRE_RESEARCH_ARTIFACTS=1 to require them`;
}
