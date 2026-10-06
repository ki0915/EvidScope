function freeze(value){if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
export const modelPolicy=freeze({
 schemaVersion:1,enabledByDefault:false,cloudAllowed:false,hostInferenceAllowed:false,tools:[],
 primary:{id:'foundation-sec',model:'fdtn-ai/Foundation-Sec-1.1-8B-Instruct',provider:'isolated-llama.cpp',artifactRepository:'fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF',revision:'0b58da4736f799f3cb5bbaffb8a39025f1c4e5df',quantization:'Q4_K_M',cpu:2,memory:'8Gi',concurrency:1,timeoutSeconds:120,contextTokens:2048,outputTokens:512},
 cipher:{id:'cipherguard',model:'smartm2m-bdg/CipherGuard-V5.0-XLM-RoBERTa',provider:'isolated-onnx',revision:null,quantization:'INT8',cpu:1,memory:'4Gi',concurrency:1,timeoutSeconds:10,contextTokens:512,maxChunks:8,overlapTokens:32},
 training:{enabledByDefault:false,rank:8,maxSequenceLength:2048,batchSize:1,minimumReviewed:{tune:300,validation:50,test:100},generatedLabelsAutomaticallyReviewed:false,humanReviewedSyntheticTrainingAllowed:true,promotionAutomatic:false}
});
export function primaryModelPolicy(){return {provider:modelPolicy.primary.provider,model:modelPolicy.primary.model,cloudAllowed:false,maxResponses:1,timeoutSeconds:120,generation:{think:false,temperature:0.1,topP:0.9,topK:20,numCtx:2048,numPredict:512,maxPromptBytes:24000}};}
