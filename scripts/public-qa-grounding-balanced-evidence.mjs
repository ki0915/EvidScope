// Verify the frozen data boundary independently of execution/adapter claims.
import {createHash} from 'node:crypto';
import {dirname,basename,resolve} from 'node:path';
import {isDeepStrictEqual as same} from 'node:util';
import {groundingArtifactChecks} from './verify-public-qa-grounding.mjs';
import {revision} from './prepare-public-qa-run.mjs';
import {STAGE,BLIND_STAGE,SOURCE_RUN,SOURCE_PINS,SOURCE_FILES,SOURCE_TRAINING_PINS,SAMPLER,SELECTION,
 selectBalancedRows,selectBalancedBlind} from './prepare-public-qa-grounding-balanced.mjs';

const {bytes}=groundingArtifactChecks;
const sha=value=>createHash('sha256').update(value).digest('hex');
const requireValue=(value,message)=>{if(!value)throw Error('balanced_evidence_'+message);};
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const parse=raw=>JSON.parse(raw.toString('utf8'));
const rows=raw=>raw.toString('utf8').split(/\r?\n/u).filter(line=>line.trim()).map(JSON.parse);
const EXPOSURES=['oldTraining','diagnostic','previousGrounding','continuation','observedFresh'];
const ROW_COUNTS={sourceManifest:null,sourceTrain:12060,sourceValidation:1345,heldout:5841,oldTraining:384,diagnostic:64,previousGrounding:704,continuation:704,observedFresh:128};
function timestamp(value){
 requireValue(typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value),'timestamp_invalid');
 const time=Date.parse(value),date=new Date(time);
 requireValue(Number.isFinite(time)&&date.toISOString().slice(0,19)===value.slice(0,19),'timestamp_invalid');return time;
}
function sourceInputBindings(workspace,inputs,sources,pins,counts){
 requireValue(Array.isArray(inputs)&&inputs.length===9&&new Set(inputs.map(item=>item?.name)).size===9
  &&same(inputs.map(item=>item.name).sort(),Object.keys(SOURCE_FILES).sort()),'source_inputs_missing');
 for(const item of inputs){
  requireValue(typeof item.path==='string'&&item.path&&item.sha256===pins[item.name]
   &&item.rows===counts[item.name]&&sha(bytes(workspace,item.path))===item.sha256,'source_input_changed:'+item.name);
  requireValue(item.name==='sourceManifest'||sources[item.name].length===item.rows,'source_input_count_changed:'+item.name);
 }
}
function commonMetadata(manifest,upstream,pins){
 requireValue(manifest.schemaVersion===1&&manifest.task==='korean_extractive_qa'&&manifest.upstreamRevision===revision
  &&manifest.license==='CC-BY-SA-4.0'&&manifest.license===upstream.license&&manifest.licenseUrl===upstream.licenseUrl
  &&manifest.attribution===upstream.attribution&&same(manifest.humanConstructionEvidence,upstream.humanConstructionEvidence)
  &&same(manifest.sourcePins,pins)&&same(manifest.sourceFiles,SOURCE_FILES),'source_identity_changed');
 requireValue(manifest.originalHumanLabelsPreserved===true&&manifest.automaticallyGeneratedLabels===false
  &&manifest.localHumanReviewPerformed===false&&manifest.qualityClaimAllowed===false&&manifest.promotionAllowed===false,'claim_boundary_changed');
}
function verifyCore({workspaceRoot=process.cwd(),inputs,manifest,dataBytes,startedAt},pins,fixture){
 requireValue(inputs&&typeof inputs.data==='string'&&typeof inputs.manifest==='string'&&manifest&&Buffer.isBuffer(dataBytes),'input_missing');
 const savedManifest=bytes(workspaceRoot,inputs.manifest),savedData=bytes(workspaceRoot,inputs.data);
 requireValue(digest(inputs.datasetSha256)&&sha(dataBytes)===inputs.datasetSha256&&sha(savedData)===inputs.datasetSha256
  &&digest(inputs.manifestSha256)&&sha(savedManifest)===inputs.manifestSha256&&same(parse(savedManifest),manifest)
  &&manifest.datasetSha256===inputs.datasetSha256,'dataset_binding_changed');
 requireValue(manifest.stage===STAGE&&manifest.runId===inputs.runId&&/^public-qa-balanced-[a-z0-9-]{1,28}$/.test(inputs.runId),'dataset_stage_changed');
 const sourceRoot=dirname(resolve(workspaceRoot,inputs.manifest)),sources={},counts={};
 for(const [key,name]of Object.entries(SOURCE_FILES)){
  const raw=bytes(sourceRoot,name);requireValue(digest(pins[key])&&sha(raw)===pins[key],'source_file_changed:'+key);
  sources[key]=key==='sourceManifest'?parse(raw):rows(raw);counts[key]=key==='sourceManifest'?null:sources[key].length;
 }
 if(!fixture)requireValue(same(counts,ROW_COUNTS),'fixed_source_counts_changed');
 const upstream=sources.sourceManifest;requireValue(upstream.revision===revision&&upstream.license==='CC-BY-SA-4.0','upstream_changed');
 commonMetadata(manifest,upstream,pins);sourceInputBindings(workspaceRoot,manifest.sourceInputs,sources,pins,counts);
 requireValue(same(manifest.counts,{train:640,validation:64})&&same(manifest.labelCounts,{train:{answerable:320,impossible:320},validation:{answerable:32,impossible:32}})
  &&same(manifest.sampler,SAMPLER)&&same(manifest.selection,SELECTION)&&manifest.heldoutUsed===false&&manifest.heldoutUsedForTraining===false
  &&manifest.wholeOfficialDevExcludedFromTraining===true&&manifest.officialDevExclusionRows===sources.heldout.length,'dataset_policy_changed');
 const source80=manifest.sourceTraining;
 requireValue(source80?.sourceRunId===SOURCE_RUN&&source80.sourceGlobalStep===20&&source80.sourceOptimizerHistoryUpdates===80
  &&source80.sourceTrainingExecutionVerified===true&&same(source80.sourcePins,SOURCE_TRAINING_PINS),'source80_metadata_changed');
 const exposed=EXPOSURES.flatMap(key=>sources[key]),selected=selectBalancedRows({train:sources.sourceTrain,validation:sources.sourceValidation},[...exposed,...sources.heldout]);
 const dataset=rows(dataBytes);
 requireValue(same(dataset,selected.rows)&&dataset.length===704&&same(manifest.rowIds,dataset.map(row=>row.id)),'original_selection_changed');
 requireValue(same(manifest.exclusions,selected.exclusions)&&same(manifest.availableCounts,selected.availableCounts)
  &&same(manifest.previousExposureOverlap,selected.previousExposureOverlap)&&manifest.exposedInputRows===exposed.length,'selection_statistics_changed');
 const experiment=manifest.experiment;
 requireValue(experiment?.plannedOptimizerSteps===20&&experiment.plannedMicrobatches===320
  &&same(experiment.plannedExposure,{answerable:160,impossible:160})&&experiment.learningRate===0.00003
  &&experiment.sourceOptimizerHistoryUpdates===80&&experiment.plannedTotalAdapterHistoryOptimizerUpdates===100
  &&experiment.lengthDistributionExpansion===true&&experiment.previousMaxContextCodepoints===650&&experiment.maxContextCodepoints===700
  &&experiment.balanceOnlyCausalComparison===false&&experiment.qualityImprovementClaimed===false,'experiment_boundary_changed');
 const freeze=timestamp(manifest.frozenAt),start=timestamp(startedAt);requireValue(freeze<start,'freeze_not_before_training');
 const binding=manifest.blindEvaluation;
 requireValue(binding&&typeof binding.directory==='string'&&binding.directory&&digest(binding.datasetSha256)&&digest(binding.manifestSha256)
  &&binding.stage===BLIND_STAGE&&binding.rows===128&&binding.trainingUsed===false&&binding.frozenAt===manifest.frozenAt,'blind_binding_changed');
 const blindRoot=resolve(workspaceRoot,binding.directory);
 requireValue(basename(blindRoot)==='blind-evaluation'&&dirname(blindRoot)===dirname(sourceRoot),'blind_not_sibling');
 const blindBytes=bytes(blindRoot,'data.jsonl'),blindManifestBytes=bytes(blindRoot,'manifest.json'),blindManifest=parse(blindManifestBytes);
 requireValue(sha(blindBytes)===binding.datasetSha256&&sha(blindManifestBytes)===binding.manifestSha256
  &&blindManifest.datasetSha256===binding.datasetSha256,'blind_file_changed');
 commonMetadata(blindManifest,upstream,pins);
 requireValue(same(blindManifest.sourceInputs,manifest.sourceInputs)&&blindManifest.stage===BLIND_STAGE
  &&blindManifest.sourceRevision===revision&&blindManifest.sourceHeldoutSha256===pins.heldout
  &&blindManifest.frozenAt===manifest.frozenAt&&timestamp(blindManifest.frozenAt)<start&&blindManifest.frozenBeforeBalancedTraining===true
  &&blindManifest.plannedTrainingRunId===inputs.runId&&blindManifest.trainingUsed===false&&blindManifest.heldoutUsedForTraining===false,'blind_scope_changed');
 const blind=selectBalancedBlind(sources.heldout,[...exposed,...sources.sourceTrain,...sources.sourceValidation,...dataset]);
 requireValue(same(rows(blindBytes),blind.rows)&&same(blindManifest.rowIds,blind.rows.map(row=>row.id))
  &&same(blindManifest.counts,{total:128,answerable:64,impossible:64})&&same(blindManifest.excluded,blind.excluded)
  &&same(blindManifest.availableCounts,blind.availableCounts)&&same(blindManifest.previousExposureOverlap,blind.overlap)
  &&blind.uniqueSelectedFamilies===128&&blind.uniqueSelectedContexts===128&&blindManifest.uniqueSelectedFamilies===128&&blindManifest.uniqueSelectedContexts===128
  &&blindManifest.exposedInputRows===exposed.length+sources.sourceTrain.length+sources.sourceValidation.length+dataset.length,'blind_original_selection_changed');
 requireValue(same(blindManifest.selection,{maxContextCodepoints:650,maxQuestionCodepoints:240,fullContextPreserved:true,answerBasedCropping:false,actualTokenizerPreadmissionRequired:true,
  algorithm:'sha256_42_fresh_evaluation_id_interleaved_labels_unique_family_context',duplicateFamiliesWithinSelection:false}),'blind_context_policy_changed');
 return dataset;
}
export const verifyBalancedDatasetBindings=options=>verifyCore(options,SOURCE_PINS,false);
// Overrides are available only through this named test-only wrapper. It emits
// no execution/completion claim even when its synthetic data boundary passes.
export function verifyBalancedDatasetBindingsFixture(options,{sourcePins}={}){
 requireValue(sourcePins&&same(Object.keys(sourcePins).sort(),Object.keys(SOURCE_PINS).sort())&&Object.values(sourcePins).every(digest),'fixture_pins_invalid');
 return {rows:verifyCore(options,sourcePins,true),syntheticFixture:true,actualTrainingExecutionVerified:false,sourceTrainingExecutionVerified:false,trainingRunCompleted:false,qualityClaimAllowed:false,promotionAllowed:false};
}
