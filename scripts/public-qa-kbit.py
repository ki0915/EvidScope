"""Prepare the selected 4-bit base without upcasting frozen vocab matrices.

This is an explicit preparation policy, not a patched quantization identifier.
Only normalization parameters are promoted to FP32. The actual QLoRA base,
adapter configuration, data, and resource admission remain the caller's job.
"""


def prepare_memory_efficient_kbit(model):
    import torch
    from bitsandbytes.nn import Params4bit

    if getattr(model, "is_loaded_in_4bit", False) is not True:
        raise ValueError("public_qa_requires_loaded_4bit_base")
    parameters = list(model.parameters())
    quantized = [parameter for parameter in parameters if isinstance(parameter, Params4bit)]
    if not quantized:
        raise ValueError("public_qa_requires_actual_4bit_parameters")
    if not callable(getattr(model, "enable_input_require_grads", None)) or not callable(getattr(model, "gradient_checkpointing_enable", None)):
        raise ValueError("public_qa_public_checkpoint_api_required")
    normalizations = set()
    for module in model.modules():
        # Covers torch LayerNorm and the selected LlamaRMSNorm without relying on
        # parameter names or changing any quantization implementation flag.
        if isinstance(module, torch.nn.LayerNorm) or type(module).__name__.endswith(("RMSNorm", "LayerNorm")):
            normalizations.update(id(parameter) for parameter in module.parameters(recurse=False))
    if not normalizations:
        raise ValueError("public_qa_normalization_parameters_missing")
    with torch.no_grad():
        for parameter in parameters:
            parameter.requires_grad_(False)
            if isinstance(parameter, Params4bit):
                continue
            if not parameter.is_floating_point():
                raise ValueError("public_qa_unexpected_nonquant_parameter_dtype")
            wanted = torch.float32 if id(parameter) in normalizations else torch.float16
            if parameter.dtype != wanted:
                parameter.data = parameter.data.to(dtype=wanted)
            if not parameter.is_contiguous():
                raise ValueError("public_qa_noncontiguous_float_parameter")
            # Bound the temporary finite-check tensor even for the 128k vocab
            # embedding/head. Never allocate a full FP32 copy of those matrices.
            flattened = parameter.detach().view(-1)
            for offset in range(0, flattened.numel(), 1024 * 1024):
                if not bool(torch.isfinite(flattened[offset:offset + 1024 * 1024]).all().item()):
                    raise ValueError("public_qa_nonfinite_base_parameter")
    model.enable_input_require_grads()
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": True})
    for parameter in parameters:
        if parameter.requires_grad:
            raise ValueError("public_qa_base_must_remain_frozen")
        if not isinstance(parameter, Params4bit):
            wanted = torch.float32 if id(parameter) in normalizations else torch.float16
            if parameter.dtype != wanted:
                raise ValueError("public_qa_base_dtype_invalid")
    return model
