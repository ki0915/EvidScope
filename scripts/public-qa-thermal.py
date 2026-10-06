"""Bounded, fail-closed cooling for the selected single-GPU training Pod.

This complements the external 80C stop guard; it does not change that guard or
control fan speed, power limits, other processes, or any host configuration.
"""
import ctypes
import time

MIN_PAUSE_SECONDS = 1.0
POLL_SECONDS = 0.5
COOLING_TRIGGER_C = 70
COOLING_TARGET_C = 65
MAX_WAIT_SECONDS = 180.0


def read_gpu_temperature():
    """Read NVML GPU index 0, matching this Pod's one visible GPU allocation."""
    nvml = ctypes.CDLL("libnvidia-ml.so.1")
    nvml.nvmlInit_v2.argtypes = []
    nvml.nvmlInit_v2.restype = ctypes.c_int
    nvml.nvmlDeviceGetHandleByIndex_v2.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)]
    nvml.nvmlDeviceGetHandleByIndex_v2.restype = ctypes.c_int
    nvml.nvmlDeviceGetTemperature.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
    nvml.nvmlDeviceGetTemperature.restype = ctypes.c_int
    nvml.nvmlShutdown.argtypes = []
    nvml.nvmlShutdown.restype = ctypes.c_int

    def checked(result, operation):
        if result != 0:
            raise RuntimeError(f"thermal_nvml_{operation}_failed:{result}")

    checked(nvml.nvmlInit_v2(), "init")
    try:
        device = ctypes.c_void_p()
        checked(nvml.nvmlDeviceGetHandleByIndex_v2(0, ctypes.byref(device)), "device")
        if not device.value:
            raise RuntimeError("thermal_nvml_device_handle_missing")
        temperature = ctypes.c_uint()
        checked(nvml.nvmlDeviceGetTemperature(device, 0, ctypes.byref(temperature)), "temperature")
        value = temperature.value
        if not 0 <= value <= 125:
            raise RuntimeError("thermal_nvml_temperature_out_of_range")
        return value
    finally:
        checked(nvml.nvmlShutdown(), "shutdown")


def wait_for_thermal_budget(torch):
    """Pause between microbatches, returning measured temperatures and wait."""
    torch.cuda.synchronize()
    started = time.monotonic()
    before = read_gpu_temperature()
    time.sleep(MIN_PAUSE_SECONDS)
    after = read_gpu_temperature()
    cooling = before >= COOLING_TRIGGER_C or after >= COOLING_TRIGGER_C
    while cooling and after > COOLING_TARGET_C:
        elapsed = time.monotonic() - started
        if elapsed >= MAX_WAIT_SECONDS:
            raise RuntimeError("thermal_cooling_deadline_exceeded")
        time.sleep(min(POLL_SECONDS, MAX_WAIT_SECONDS - elapsed))
        after = read_gpu_temperature()
    elapsed = time.monotonic() - started
    if elapsed > MAX_WAIT_SECONDS:
        raise RuntimeError("thermal_cooling_deadline_exceeded")
    return {"before": before, "after": after, "waitSeconds": elapsed}
