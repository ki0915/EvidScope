"""Opt-in loader experiment. Never imported by the sealed training runtime.

Only pinned Transformers 4.51.3, original BF16 safetensors and single-device
bnb NF4 loading are supported. This changes transient loading, not weights.
"""
from contextlib import contextmanager
import hashlib
import importlib.metadata
import json
from pathlib import Path
import threading

SOURCE_SHA256 = 'bf3f2b4314492a5148d69bde5ef23dbe0c63a9224970b5e83a22af0d10269a0c'
VERSIONS = {'transformers': '4.51.3', 'bitsandbytes': '0.45.5',
            'safetensors': '0.5.3', 'accelerate': '1.6.0'}
_LOCK = threading.Lock()


class DeferredSafetensor:
    """Only dtype/shape metadata is retained until Transformers calls .to()."""
    def __init__(self, path, name, shape, dtype, observer=None, capability=None):
        self.path = path
        self.name = name
        self.shape = tuple(shape)
        self.dtype = dtype
        self._observer = observer
        self._capability = capability
        stat = path.stat()
        self._file_identity = (stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def to(self, device):
        from safetensors import safe_open
        import torch
        if self._capability is not None and (not self._capability['active']
                or self._capability['thread'] != threading.get_ident()):
            raise RuntimeError('streaming_tensor_scope_inactive')
        stat = self.path.stat()
        if (stat.st_ino, stat.st_size, stat.st_mtime_ns) != self._file_identity:
            raise RuntimeError('streaming_checkpoint_file_changed')
        if isinstance(device, int):
            device = f'cuda:{device}'
        device = str(torch.device(device))
        if device not in ('cpu', 'cuda:0'):
            raise RuntimeError('streaming_tensor_device_unsupported')
        with safe_open(str(self.path), framework='pt', device=device) as archive:
            value = archive.get_tensor(self.name)
        if tuple(value.shape) != self.shape or value.dtype != self.dtype:
            raise RuntimeError('streaming_tensor_metadata_changed')
        if self._observer:
            self._observer(self.name, value.numel() * value.element_size(), device)
        return value


def deferred_state_dict(path, *, observer=None, capability=None):
    from safetensors import safe_open
    from transformers.modeling_utils import str_to_torch_dtype
    path = Path(path).resolve(strict=True)
    if path.suffix != '.safetensors':
        raise RuntimeError('streaming_requires_safetensors')
    with safe_open(str(path), framework='pt', device='cpu') as archive:
        metadata = archive.metadata()
        if metadata is None or metadata.get('format') != 'pt':
            raise RuntimeError('streaming_requires_pytorch_metadata')
        values = {}
        for name in archive.keys():
            section = archive.get_slice(name)
            # Original model only. Serialized quantization state is unsupported.
            if section.get_dtype() != 'BF16' or '.quant_state.' in name:
                raise RuntimeError('streaming_requires_original_bf16_weights')
            values[name] = DeferredSafetensor(path, name, section.get_shape(),
                                             str_to_torch_dtype['BF16'], observer, capability)
        return values


@contextmanager
def streaming_bf16_nf4_load(model_directory, *, observer=None):
    """Temporary process-local hook; no installed package/file is modified.

    Caller must use from_pretrained(... device_map={'': 0}, torch_dtype=BF16,
    quantization_config=NF4/double-quant). This candidate is not admitted for
    training until real NF4 equality and peak-memory comparisons pass.
    """
    import transformers.modeling_utils as modeling
    for package, version in VERSIONS.items():
        if importlib.metadata.version(package) != version:
            raise RuntimeError('streaming_library_version_changed')
    if hashlib.sha256(Path(modeling.__file__).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise RuntimeError('streaming_loader_source_changed')
    root = Path(model_directory).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError('streaming_model_directory_invalid')
    if not _LOCK.acquire(blocking=False):
        raise RuntimeError('streaming_load_already_active')
    original = modeling.load_state_dict
    owner_thread = threading.get_ident()
    capability = {'active': True, 'thread': owner_thread}

    def load(checkpoint_file, is_quantized=False, map_location='cpu', weights_only=True):
        path = Path(checkpoint_file).resolve(strict=True)
        if is_quantized and map_location == 'cpu':
            if threading.get_ident() != owner_thread or not path.is_relative_to(root) or not weights_only:
                raise RuntimeError('streaming_checkpoint_scope_invalid')
            return deferred_state_dict(path, observer=observer, capability=capability)
        return original(checkpoint_file, is_quantized=is_quantized,
                        map_location=map_location, weights_only=weights_only)

    body_error = None
    try:
        modeling.load_state_dict = load
        yield
    except BaseException as error:
        body_error = error
        raise
    finally:
        capability['active'] = False
        # A concurrent third-party replacement must not be silently overwritten.
        owned = modeling.load_state_dict is load
        if owned:
            modeling.load_state_dict = original
        _LOCK.release()
        if not owned:
            if body_error is not None:
                body_error.add_note('streaming_hook_ownership_changed; external hook preserved')
            else:
                raise RuntimeError('streaming_hook_ownership_changed')


def load_streaming_bf16_nf4_model(model_directory, *, observer=None):
    """Fixed experiment entry point; CPU/offload/other quantizers are disallowed."""
    import torch
    from transformers import AutoModelForCausalLM, BitsAndBytesConfig
    import transformers.modeling_utils as modeling
    configuration = json.loads((Path(model_directory) / 'config.json').read_text())
    if (configuration.get('model_type') != 'llama'
            or configuration.get('architectures') != ['LlamaForCausalLM']
            or configuration.get('torch_dtype') != 'bfloat16'
            or 'quantization_config' in configuration
            or configuration.get('pretraining_tp', 1) != 1):
        raise RuntimeError('streaming_model_architecture_unsupported')
    if modeling.is_fsdp_enabled() or modeling.is_deepspeed_zero3_enabled() or torch.distributed.is_initialized():
        raise RuntimeError('streaming_distributed_load_unsupported')
    if not torch.cuda.is_available() or not torch.cuda.is_bf16_supported():
        raise RuntimeError('streaming_bf16_cuda_required')
    with streaming_bf16_nf4_load(model_directory, observer=observer):
        model = AutoModelForCausalLM.from_pretrained(
            model_directory, local_files_only=True, trust_remote_code=False,
            device_map={'': 0}, torch_dtype=torch.bfloat16, attn_implementation='sdpa',
            quantization_config=BitsAndBytesConfig(
                load_in_4bit=True, bnb_4bit_quant_type='nf4',
                bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.bfloat16))
    if any(parameter.is_meta for parameter in model.parameters()):
        raise RuntimeError('streaming_weights_not_materialized')
    return model
