from __future__ import annotations

import gzip
import os
from dataclasses import dataclass, field
from typing import Sequence

if os.environ.get("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION") != "python":
    os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedFrame,
    CapturedSample,
)
from opentelemetry.sdk.extension.profiling.export import pprof_pb2
from opentelemetry.sdk.resources import Resource


@dataclass
class _PprofDictionary:
    strings: list[str] = field(default_factory=lambda: [""])
    string_indices: dict[str, int] = field(default_factory=lambda: {"": 0})
    functions: list[pprof_pb2.Function] = field(default_factory=list)
    function_indices: dict[tuple[int, int, int], int] = field(
        default_factory=dict
    )
    locations: list[pprof_pb2.Location] = field(default_factory=list)
    location_indices: dict[tuple[int, int], int] = field(default_factory=dict)

    def intern_string(self, value: str) -> int:
        if value not in self.string_indices:
            index = len(self.strings)
            self.strings.append(value)
            self.string_indices[value] = index
        return self.string_indices[value]

    def intern_function(
        self, name: str, filename: str, start_line: int
    ) -> int:
        name_index = self.intern_string(name)
        filename_index = self.intern_string(filename)
        identity = (name_index, filename_index, start_line)
        if identity in self.function_indices:
            return self.function_indices[identity]

        function = pprof_pb2.Function(
            id=len(self.functions) + 1,
            name=name_index,
            system_name=name_index,
            filename=filename_index,
            start_line=start_line,
        )
        self.functions.append(function)
        self.function_indices[identity] = function.id
        return function.id

    def intern_location(
        self, function_id: int, line_number: int, mapping_id: int = 0
    ) -> int:
        identity = (function_id, line_number, mapping_id)
        if identity in self.location_indices:
            return self.location_indices[identity]

        loc = pprof_pb2.Location(
            id=len(self.locations) + 1,
            mapping_id=mapping_id,
            address=0,
        )
        line = pprof_pb2.Line(function_id=function_id, line=line_number)
        loc.line.append(line)
        self.locations.append(loc)
        self.location_indices[identity] = loc.id
        return loc.id


class PprofProfileBuilder:
    def build(
        self,
        *,
        samples: list[CapturedSample],
        resource: Resource | None = None,
        sample_period_ns: int,
    ) -> bytes:
        del resource
        if not samples:
            profile = pprof_pb2.Profile()
            profile.period = sample_period_ns
            return gzip.compress(profile.SerializeToString())

        dictionary = _PprofDictionary()
        profile = pprof_pb2.Profile()
        profile.period = sample_period_ns
        profile.period_type.type = dictionary.intern_string("wall")
        profile.period_type.unit = dictionary.intern_string("nanoseconds")

        sample_type_indices: dict[tuple[str, str], int] = {}
        for sample in samples:
            key = (sample.sample_type, sample.sample_unit)
            if key not in sample_type_indices:
                sample_type_indices[key] = len(sample_type_indices)
                sample_type = profile.sample_type.add()
                sample_type.type = dictionary.intern_string(key[0])
                sample_type.unit = dictionary.intern_string(key[1])

        string_times = [sample.timestamp_unix_nano for sample in samples]
        profile.time_nanos = min(string_times)
        profile.duration_nanos = max(string_times) - profile.time_nanos

        for sample in samples:
            values = [0] * len(sample_type_indices)
            index = sample_type_indices[
                (sample.sample_type, sample.sample_unit)
            ]
            values[index] = sample.value

            labels = self._build_labels(sample, dictionary)
            location_ids = self._location_ids(sample.frames, dictionary)

            sample_msg = pprof_pb2.Sample(
                location_id=location_ids,
                value=values,
                label=labels,
            )
            profile.sample.append(sample_msg)

        profile.string_table.extend(dictionary.strings)
        profile.function.extend(dictionary.functions)
        profile.location.extend(dictionary.locations)
        return gzip.compress(profile.SerializeToString())

    def _location_ids(
        self, frames: tuple[CapturedFrame, ...], dictionary: _PprofDictionary
    ) -> Sequence[int]:
        locations = []
        for frame in frames:
            function_id = dictionary.intern_function(
                frame.function, frame.filename, frame.lineno
            )
            location_id = dictionary.intern_location(function_id, frame.lineno)
            locations.append(location_id)
        return locations

    def _build_labels(
        self, sample: CapturedSample, dictionary: _PprofDictionary
    ) -> Sequence[pprof_pb2.Label]:
        labels: list[pprof_pb2.Label] = []
        for key, value in (
            ("thread id", sample.thread_id),
            ("thread name", sample.thread_name),
        ):
            labels.append(self._value_label(key, value, dictionary))

        if sample.trace_id:
            labels.append(
                self._value_label(
                    "trace id",
                    f"{sample.trace_id:032x}",
                    dictionary,
                )
            )
        if sample.span_id:
            labels.append(
                self._value_label(
                    "span id",
                    f"{sample.span_id:016x}",
                    dictionary,
                )
            )
        if sample.local_root_span_id:
            labels.append(
                self._value_label(
                    "local root span id",
                    sample.local_root_span_id,
                    dictionary,
                )
            )
        if sample.trace_type:
            labels.append(
                self._value_label(
                    "trace type",
                    sample.trace_type,
                    dictionary,
                )
            )
        if sample.trace_endpoint:
            labels.append(
                self._value_label(
                    "trace endpoint",
                    sample.trace_endpoint,
                    dictionary,
                )
            )
        if sample.class_name:
            labels.append(
                self._value_label(
                    "class name",
                    sample.class_name,
                    dictionary,
                )
            )
        if sample.task_id:
            labels.append(
                self._value_label(
                    "task id",
                    sample.task_id,
                    dictionary,
                )
            )
        if sample.task_name:
            labels.append(
                self._value_label(
                    "task name",
                    sample.task_name,
                    dictionary,
                )
            )

        for attribute in sample.attributes:
            key = self._normalize_attribute_key(attribute.key)
            label = self._value_label(
                key, attribute.value, dictionary, attribute.unit
            )
            labels.append(label)

        return labels

    def _value_label(
        self,
        key: str,
        value: object,
        dictionary: _PprofDictionary,
        unit: str = "",
    ) -> pprof_pb2.Label:
        label = pprof_pb2.Label()
        label.key = dictionary.intern_string(key)
        if isinstance(value, int):
            label.num = value
            if unit:
                label.num_unit = dictionary.intern_string(unit)
        else:
            label.str = dictionary.intern_string(str(value))
        return label

    def _normalize_attribute_key(self, key: str) -> str:
        if "." in key:
            return key.replace(".", " ")
        return key


_COMPATIBLE_PYTHON_SAMPLE_TYPES = (
    ("cpu-samples", "count"),
    ("cpu-time", "nanoseconds"),
    ("wall-time", "nanoseconds"),
    ("exception-samples", "count"),
    ("lock-acquire", "count"),
    ("lock-acquire-wait", "nanoseconds"),
    ("lock-release", "count"),
    ("lock-release-hold", "nanoseconds"),
    ("heap-space", "bytes"),
)


class CompatiblePprofProfileBuilder(PprofProfileBuilder):
    def build(
        self,
        *,
        samples: list[CapturedSample],
        resource: Resource | None = None,
        sample_period_ns: int,
    ) -> bytes:
        if not samples:
            profile = pprof_pb2.Profile()
            profile.period = sample_period_ns
            profile.period_type.type = 0
            profile.period_type.unit = 0
            return gzip.compress(profile.SerializeToString())

        dictionary = _PprofDictionary()
        profile = pprof_pb2.Profile()
        profile.period = sample_period_ns
        profile.period_type.type = dictionary.intern_string("time")
        profile.period_type.unit = dictionary.intern_string("nanoseconds")

        for sample_type_name, sample_unit in _COMPATIBLE_PYTHON_SAMPLE_TYPES:
            sample_type = profile.sample_type.add()
            sample_type.type = dictionary.intern_string(sample_type_name)
            sample_type.unit = dictionary.intern_string(sample_unit)

        string_times = [sample.timestamp_unix_nano for sample in samples]
        profile.time_nanos = min(string_times)
        profile.duration_nanos = max(string_times) - profile.time_nanos

        mapping_id = self._add_mapping(profile, dictionary, samples, resource)

        for sample in samples:
            values = self._compat_values(sample, sample_period_ns)
            if not any(values):
                continue
            sample_msg = pprof_pb2.Sample(
                location_id=self._compat_location_ids(
                    sample.frames, dictionary, mapping_id
                ),
                value=values,
                label=self._compat_labels(sample, dictionary),
            )
            profile.sample.append(sample_msg)

        profile.string_table.extend(dictionary.strings)
        profile.function.extend(dictionary.functions)
        profile.location.extend(dictionary.locations)
        return gzip.compress(profile.SerializeToString())

    def _add_mapping(
        self,
        profile: pprof_pb2.Profile,
        dictionary: _PprofDictionary,
        samples: list[CapturedSample],
        resource: Resource | None,
    ) -> int:
        filename = None
        if resource is not None:
            filename = resource.attributes.get("service.name")
        if not filename:
            for sample in samples:
                for frame in sample.frames:
                    if frame.filename:
                        filename = frame.filename
                        break
                if filename:
                    break
        if not filename:
            filename = "python"

        mapping = profile.mapping.add()
        mapping.id = 1
        mapping.filename = dictionary.intern_string(str(filename))
        mapping.has_functions = True
        mapping.has_filenames = True
        mapping.has_line_numbers = True
        return mapping.id

    def _compat_location_ids(
        self,
        frames: tuple[CapturedFrame, ...],
        dictionary: _PprofDictionary,
        mapping_id: int,
    ) -> Sequence[int]:
        locations = []
        for frame in frames:
            function_id = dictionary.intern_function(
                frame.function, frame.filename, frame.lineno
            )
            location_id = dictionary.intern_location(
                function_id, frame.lineno, mapping_id
            )
            locations.append(location_id)
        return locations

    def _compat_values(
        self, sample: CapturedSample, sample_period_ns: int
    ) -> Sequence[int]:
        values = [0] * len(_COMPATIBLE_PYTHON_SAMPLE_TYPES)

        if sample.sample_type == "samples":
            if sample.cpu_time_ns > 0:
                values[0] = sample.value
                values[1] = sample.cpu_time_ns
            values[2] = sample.value * sample_period_ns
            return values

        if sample.sample_type == "exceptions":
            values[3] = sample.value
            return values

        if sample.sample_type in (
            "lock.acquire.duration",
            "lock.wait.duration",
        ):
            values[4] = max(1, sample.period)
            values[5] = sample.value * max(1, sample.period)
            return values

        if sample.sample_type == "lock.hold.duration":
            values[6] = max(1, sample.period)
            values[7] = sample.value * max(1, sample.period)
            return values

        if sample.sample_type == "memory.heap.bytes":
            values[8] = sample.value
            return values

        return values

    def _compat_labels(
        self, sample: CapturedSample, dictionary: _PprofDictionary
    ) -> Sequence[pprof_pb2.Label]:
        labels: list[pprof_pb2.Label] = []
        for key, value in (
            ("thread id", sample.thread_id),
            ("thread name", sample.thread_name),
        ):
            labels.append(self._string_label(key, value, dictionary))

        if sample.trace_id:
            labels.append(
                self._string_label(
                    "trace id",
                    f"{sample.trace_id:032x}",
                    dictionary,
                )
            )
        if sample.span_id:
            labels.append(
                self._string_label(
                    "span id",
                    f"{sample.span_id:016x}",
                    dictionary,
                )
            )
        if sample.local_root_span_id:
            labels.append(
                self._string_label(
                    "local root span id",
                    sample.local_root_span_id,
                    dictionary,
                )
            )
        if sample.trace_type:
            labels.append(
                self._string_label(
                    "trace type",
                    sample.trace_type,
                    dictionary,
                )
            )
        if sample.trace_endpoint:
            labels.append(
                self._string_label(
                    "trace endpoint",
                    sample.trace_endpoint,
                    dictionary,
                )
            )
        if sample.class_name:
            labels.append(
                self._string_label(
                    "class name",
                    sample.class_name,
                    dictionary,
                )
            )
        if sample.task_id is not None:
            labels.append(
                self._string_label(
                    "task id",
                    sample.task_id,
                    dictionary,
                )
            )
        if sample.task_name:
            labels.append(
                self._string_label(
                    "task name",
                    sample.task_name,
                    dictionary,
                )
            )

        for attribute in sample.attributes:
            labels.append(
                self._string_label(
                    self._normalize_attribute_key(attribute.key),
                    attribute.value,
                    dictionary,
                )
            )

        return labels

    def _string_label(
        self,
        key: str,
        value: object,
        dictionary: _PprofDictionary,
    ) -> pprof_pb2.Label:
        label = pprof_pb2.Label()
        label.key = dictionary.intern_string(key)
        label.str = dictionary.intern_string(str(value))
        return label
