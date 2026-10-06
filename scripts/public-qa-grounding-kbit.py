"""Grounding-only BF16 preparation; original FP16 runtime stays byte-identical."""
def prepare_grounding_bf16_kbit(model):
    import torch
    from bitsandbytes.nn import Params4bit
    if getattr(model,'is_loaded_in_4bit',False) is not True:
        raise ValueError('grounding_requires_loaded_4bit_base')
    parameters=list(model.parameters())
    if not any(isinstance(p,Params4bit) for p in parameters):
        raise ValueError('grounding_requires_actual_4bit_parameters')
    if not callable(getattr(model,'enable_input_require_grads',None)) or not callable(getattr(model,'gradient_checkpointing_enable',None)):
        raise ValueError('grounding_checkpoint_api_required')
    norms=set()
    for module in model.modules():
        if isinstance(module,torch.nn.LayerNorm) or type(module).__name__.endswith(('RMSNorm','LayerNorm')):
            norms.update(id(p) for p in module.parameters(recurse=False))
    if not norms:
        raise ValueError('grounding_normalization_parameters_missing')
    with torch.no_grad():
        for parameter in parameters:
            parameter.requires_grad_(False)
            if isinstance(parameter,Params4bit):
                continue
            if not parameter.is_floating_point():
                raise ValueError('grounding_nonquant_dtype_invalid')
            wanted=torch.float32 if id(parameter) in norms else torch.bfloat16
            if parameter.dtype!=wanted:
                parameter.data=parameter.data.to(dtype=wanted)
            if not parameter.is_contiguous():
                raise ValueError('grounding_float_parameter_noncontiguous')
            flat=parameter.detach().view(-1)
            for offset in range(0,flat.numel(),1024*1024):
                if not bool(torch.isfinite(flat[offset:offset+1024*1024]).all().item()):
                    raise ValueError('grounding_base_parameter_nonfinite')
    model.enable_input_require_grads()
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={'use_reentrant':True})
    for parameter in parameters:
        if parameter.requires_grad:
            raise ValueError('grounding_base_must_remain_frozen')
        if not isinstance(parameter,Params4bit) and parameter.dtype!=(torch.float32 if id(parameter) in norms else torch.bfloat16):
            raise ValueError('grounding_base_dtype_invalid')
    return model
