import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("public_qa_thermal", Path(__file__).resolve().parents[1] / "scripts/public-qa-thermal.py")
thermal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(thermal)


class NativeFunction:
    def __init__(self, function):
        self.function = function
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.function(*args)


class FakeNvml:
    def __init__(self, *, temperature=72, init_code=0, device_code=0, temp_code=0, shutdown_code=0):
        self.nvmlInit_v2 = NativeFunction(lambda: init_code)
        def device(index, out):
            out._obj.value = 123
            return device_code
        def read(handle, sensor, out):
            out._obj.value = temperature
            return temp_code
        self.nvmlDeviceGetHandleByIndex_v2 = NativeFunction(device)
        self.nvmlDeviceGetTemperature = NativeFunction(read)
        self.nvmlShutdown = NativeFunction(lambda: shutdown_code)


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []
    def monotonic(self):
        return self.now
    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class ThermalTests(unittest.TestCase):
    def test_nvml_success_checks_actual_pointer_value_and_shuts_down(self):
        library = FakeNvml()
        with patch.object(thermal.ctypes, "CDLL", return_value=library):
            self.assertEqual(thermal.read_gpu_temperature(), 72)
        self.assertEqual(len(library.nvmlShutdown.calls), 1)
        self.assertEqual(library.nvmlDeviceGetTemperature.calls[0][1], 0)

    def test_every_nvml_failure_is_closed_and_initialized_library_is_cleaned(self):
        for argument, operation in (("init_code", "init"), ("device_code", "device"), ("temp_code", "temperature"), ("shutdown_code", "shutdown")):
            with self.subTest(operation=operation):
                library = FakeNvml(**{argument: 7})
                with patch.object(thermal.ctypes, "CDLL", return_value=library), self.assertRaisesRegex(RuntimeError, f"{operation}_failed:7"):
                    thermal.read_gpu_temperature()
                self.assertEqual(len(library.nvmlShutdown.calls), 0 if operation == "init" else 1)

    def test_temperature_out_of_range_is_not_accepted(self):
        library = FakeNvml(temperature=999)
        with patch.object(thermal.ctypes, "CDLL", return_value=library), self.assertRaisesRegex(RuntimeError, "out_of_range"):
            thermal.read_gpu_temperature()
        self.assertEqual(len(library.nvmlShutdown.calls), 1)

    def test_cooling_has_hysteresis_and_minimum_pause(self):
        clock, cuda = Clock(), SimpleNamespace(synchronize=Mock())
        with patch.object(thermal.time, "monotonic", clock.monotonic), patch.object(thermal.time, "sleep", clock.sleep), patch.object(thermal, "read_gpu_temperature", side_effect=[72, 69, 66, 65]):
            result = thermal.wait_for_thermal_budget(SimpleNamespace(cuda=cuda))
        self.assertEqual(result, {"before": 72, "after": 65, "waitSeconds": 2.0})
        self.assertEqual(clock.sleeps, [1.0, 0.5, 0.5])
        cuda.synchronize.assert_called_once()

    def test_cool_gpu_still_pauses_and_lookup_failure_propagates(self):
        clock = Clock()
        torch = SimpleNamespace(cuda=SimpleNamespace(synchronize=Mock()))
        with patch.object(thermal.time, "monotonic", clock.monotonic), patch.object(thermal.time, "sleep", clock.sleep), patch.object(thermal, "read_gpu_temperature", return_value=60):
            self.assertEqual(thermal.wait_for_thermal_budget(torch)["waitSeconds"], 1.0)
        with patch.object(thermal, "read_gpu_temperature", side_effect=RuntimeError("unavailable")), self.assertRaisesRegex(RuntimeError, "unavailable"):
            thermal.wait_for_thermal_budget(torch)

    def test_uncooled_gpu_stops_at_deadline(self):
        clock = Clock()
        torch = SimpleNamespace(cuda=SimpleNamespace(synchronize=Mock()))
        with patch.object(thermal.time, "monotonic", clock.monotonic), patch.object(thermal.time, "sleep", clock.sleep), patch.object(thermal, "read_gpu_temperature", return_value=75), self.assertRaisesRegex(RuntimeError, "deadline_exceeded"):
            thermal.wait_for_thermal_budget(torch)
        self.assertEqual(clock.now, 180.0)


if __name__ == "__main__":
    unittest.main()
