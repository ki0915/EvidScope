# 엔터프라이즈 증적·한국법 적용 후보·저메모리 학습 후속

2026-09-29. 이번 단계는 **progress**이며 전체 엔터프라이즈 준비나 법적 준수 완료가 아니다.

## 제품 변경

- 일반 overview·action·alerts와 `/api/integrity`가 signed ledger의 평가와 SQL `evaluations` 사본의 행 수, 순서, `action_id`, `version`, canonical body를 같은 SQLite snapshot에서 대조한다. 불일치하면 조작된 평가를 반환하지 않는다.
- 공통 평가 사본 검사기를 금융 보고서와 vault backup에도 사용한다. `/api/integrity`는 `evaluation_projections`를 검사 범위로 올렸고 `development_run_projections`, `event_indexes`, `document_files`는 계속 미검사 범위로 표시한다.
- 한국 AI 기본법 적용 후보 평가는 assessment 작성 시 서버가 계산한 정책 버전, 요구사항·시스템 해시, 후보 결과와 snapshot SHA-256을 signed record에 고정한다. 클라이언트가 보낸 provenance 값은 사용하지 않는다.
- 현재 정책·사실·후보 계산이 평가 시점과 다르면 사람의 `applicability`, `assessment`, `legalReview` 결론을 바꾸지 않고 `review_required`와 signed 재검토 과제를 만든다.
- signed 금융 보고서는 적용 후보 정책 버전과 catalog identity hash, 평가시점 governance snapshot을 고정한다. 이는 법적 적용성이나 준수 자동 판정이 아니다.

## 저메모리 학습 경로

- 길이 1024, rank 8, NF4, batch 1, 누적 16, 데이터 384행, step-20 원본은 유지했다.
- 마스킹된 prompt 위치의 128,276개 vocabulary logits와 FP32 cross-entropy를 만들지 않고 supervised completion 위치에 대해서만 동일 causal loss를 계산한다.
- batch 1, 연속 completion mask, input/label 일치와 마지막 EOS를 fail-closed로 검사한다.
- 고정 학습 이미지의 tiny Llama+PEFT에서 full/selective loss, 선택 logits, LoRA gradient가 허용 오차 내 일치했고 0-LR optimizer step 뒤 trainable parameters가 bitwise unchanged였다.
- 새 target은 `public-qa-stage2-lowmem-20260929-r2`, provenance SHA-256은 `10f1f76497603dbfaf5e4ab35eb21392ffbfee944fed0a92ab16f4119cc99223`, runtime SHA-256은 `ce78295408da160e5e1bb312b345d65ebbb45a0bd145551894dbaf5993616ce9`다. 기존 step-20 checkpoint marker `8aa6594ec8a86f13ad1593304de88b246d000b797e525d8bc9a8eed887fff81c`는 변경하지 않았다.

3회 실제 사전 검사는 Windows commit 여유 `8.299 / 8.331 / 8.429 GiB`, 물리 메모리 `10.339 / 10.287 / 10.361 GiB`, GPU 사용 `2968 / 2968 / 2964 MiB`였다. 이전 실제 역전파는 commit을 약 10.4 GiB 낮췄으므로 14 GiB 시작 기준을 유지했다. 결과는 `blocked_resources`; Job, Pod, candidate, active lease는 생성되지 않았다. selective logits의 실제 GPU/commit 절감량은 자원 파일럿을 실행하기 전까지 미측정이다.

## 검증

- 제품 집중 host 테스트: 103/103
- 새 제품 이미지 `evidscope:enterprise-20260929-r3`, image ID `sha256:ef9b89f4470e12ae5c81f49c730ddf60c08e56de17e3ee28e4a43f2ae2054279`
- 위 이미지의 UID 1000, read-only root, 외부 network 차단, CPU 2, RAM 1 GiB 검증: 103/103
- 고정 학습 이미지 Python/Torch/Transformers 공개-QA 테스트: 73/73
- Node stage-2/controller/resource policy 테스트: 25/25
- 전체 host batch: 479개 중 468개 통과. 11개는 Windows `listen EFAULT`와 그 연쇄 실패였다. 실패 파일을 분리 실행하거나 Linux 컨테이너에서 재검증했고 변경 관련 assertion 실패는 재현되지 않았다. TLS는 host 분리 재실행 8/8 통과했다.

## 실행 상태와 남은 범위

- 학습 전용 노드는 정지 상태이고 active training lease는 없다.
- 임시 정지한 DLP 컨테이너 중 5개는 같은 ID로 복구했다. `k3d-dlp-serverlb`는 AhnLab Safe Transaction Service가 기존 host port `58670`을 점유해 시작하지 못했다. 보안 서비스를 임의 중지하거나 컨테이너를 삭제·재생성하지 않았다.
- 실제 학습은 commit 여유 14 GiB를 3회 충족한 뒤 새 selective-logits 0-LR 파일럿으로 peak를 측정하고, 같은 provenance로 step 21–40을 실행해야 한다.
- 외부 공급사·금융 업무 실연동, 장기 보존 경과 증명, remote immutable storage/KMS/HA, 실제 조직 IdP, 경쟁 도구 동일입력 비교, 한국어 의미·안전 사람 검토는 남아 있다.
