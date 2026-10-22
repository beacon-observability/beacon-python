# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import uuid4

from opentelemetry.exporter.otlp.proto.common._internal import (
    _encode_instrumentation_scope,
    _encode_resource,
    _encode_span_id,
    _encode_trace_id,
    _encode_value,
)
from opentelemetry.proto.collector.profiles.v1development.profiles_service_pb2 import (
    ExportProfilesServiceRequest,
)
from opentelemetry.proto.profiles.v1development.profiles_pb2 import (
    Function,
    KeyValueAndUnit,
    Line,
    Link,
    Location,
    Mapping,
    Profile,
    ProfilesDictionary,
    ResourceProfiles,
    Sample,
    ScopeProfiles,
    Stack,
    ValueType,
)
from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedFrame,
    CapturedSample,
)
from opentelemetry.sdk.extension.profiling.version import __version__
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.util.instrumentation import InstrumentationScope


@dataclass
class _SampleBucket:
    values: list[int] = field(default_factory=list)
    timestamps_unix_nano: list[int] = field(default_factory=list)


@dataclass
class _ProfileBucket:
    sample_type: str
    sample_unit: str
    period_type: str
    period_unit: str
    period: int
    sample_buckets: dict[tuple[int, tuple[int, ...], int], _SampleBucket] = (
        field(default_factory=dict)
    )
    timestamps_unix_nano: list[int] = field(default_factory=list)


class ProfilesRequestBuilder:
    def __init__(self) -> None:
        self._scope = InstrumentationScope(
            name="opentelemetry.sdk.extension.profiling",
            version=__version__,
        )

    def build(
        self,
        samples: list[CapturedSample],
        resource: Resource,
        sample_period_ns: int,
    ) -> ExportProfilesServiceRequest:
        dictionary = _DictionaryBuilder()
        profile_buckets: dict[
            tuple[str, str, str, str, int], _ProfileBucket
        ] = {}

        for sample in samples:
            resolved_period = sample.period or sample_period_ns
            profile_key = (
                sample.sample_type,
                sample.sample_unit,
                sample.period_type,
                sample.period_unit,
                resolved_period,
            )
            profile_bucket = profile_buckets.setdefault(
                profile_key,
                _ProfileBucket(
                    sample_type=sample.sample_type,
                    sample_unit=sample.sample_unit,
                    period_type=sample.period_type,
                    period_unit=sample.period_unit,
                    period=resolved_period,
                ),
            )
            stack_index = dictionary.intern_stack(sample.frames)
            attribute_indices = tuple(
                [
                    dictionary.intern_attribute("thread.id", sample.thread_id),
                    dictionary.intern_attribute(
                        "thread.name", sample.thread_name
                    ),
                    *[
                        dictionary.intern_attribute(
                            attribute.key,
                            attribute.value,
                            attribute.unit,
                        )
                        for attribute in sample.attributes
                    ],
                ]
            )
            link_index = dictionary.intern_link(
                sample.trace_id, sample.span_id
            )
            bucket = profile_bucket.sample_buckets.setdefault(
                (stack_index, attribute_indices, link_index),
                _SampleBucket(),
            )
            bucket.values.append(sample.value)
            bucket.timestamps_unix_nano.append(sample.timestamp_unix_nano)
            profile_bucket.timestamps_unix_nano.append(
                sample.timestamp_unix_nano
            )

        profiles = [
            self._build_profile(bucket, dictionary)
            for bucket in profile_buckets.values()
        ]

        scope_profiles = ScopeProfiles(
            scope=_encode_instrumentation_scope(self._scope),
            profiles=profiles,
            schema_url=self._scope.schema_url or "",
        )
        resource_profiles = ResourceProfiles(
            resource=_encode_resource(resource),
            scope_profiles=[scope_profiles],
            schema_url=resource.schema_url or "",
        )
        return ExportProfilesServiceRequest(
            resource_profiles=[resource_profiles],
            dictionary=dictionary.build(),
        )

    def _build_profile(
        self,
        bucket: _ProfileBucket,
        dictionary: "_DictionaryBuilder",
    ) -> Profile:
        start_time = min(bucket.timestamps_unix_nano)
        end_time = max(bucket.timestamps_unix_nano)
        duration = max(end_time - start_time, bucket.period)

        profile_samples = []
        for (
            stack_index,
            attribute_indices,
            link_index,
        ), sample_bucket in bucket.sample_buckets.items():
            profile_samples.append(
                Sample(
                    stack_index=stack_index,
                    values=sample_bucket.values,
                    attribute_indices=attribute_indices,
                    link_index=link_index,
                    timestamps_unix_nano=sample_bucket.timestamps_unix_nano,
                )
            )

        return Profile(
            sample_type=ValueType(
                type_strindex=dictionary.intern_string(bucket.sample_type),
                unit_strindex=dictionary.intern_string(bucket.sample_unit),
            ),
            samples=profile_samples,
            time_unix_nano=start_time,
            duration_nano=duration,
            period_type=ValueType(
                type_strindex=dictionary.intern_string(bucket.period_type),
                unit_strindex=dictionary.intern_string(bucket.period_unit),
            ),
            period=bucket.period,
            profile_id=uuid4().bytes,
        )


class _DictionaryBuilder:
    def __init__(self) -> None:
        self._strings = [""]
        self._string_indices = {"": 0}

        self._functions: list[Function] = [Function()]
        self._function_indices: dict[tuple[str, str, str, int], int] = {
            ("", "", "", 0): 0
        }

        self._locations: list[Location] = [Location()]
        self._location_indices: dict[tuple[int, int], int] = {}

        self._stacks: list[Stack] = [Stack()]
        self._stack_indices: dict[tuple[int, ...], int] = {(): 0}

        self._attributes: list[KeyValueAndUnit] = [KeyValueAndUnit()]
        self._attribute_indices: dict[tuple[str, object, str], int] = {}

        self._links = [Link()]
        self._link_indices: dict[tuple[int, int], int] = {(0, 0): 0}

    def build(self) -> ProfilesDictionary:
        return ProfilesDictionary(
            mapping_table=[Mapping()],
            string_table=self._strings,
            function_table=self._functions,
            location_table=self._locations,
            stack_table=self._stacks,
            attribute_table=self._attributes,
            link_table=self._links,
        )

    def intern_string(self, value: str) -> int:
        if value not in self._string_indices:
            self._string_indices[value] = len(self._strings)
            self._strings.append(value)
        return self._string_indices[value]

    def intern_attribute(self, key: str, value: object, unit: str = "") -> int:
        identity = (key, value, unit)
        if identity not in self._attribute_indices:
            self._attribute_indices[identity] = len(self._attributes)
            self._attributes.append(
                KeyValueAndUnit(
                    key_strindex=self.intern_string(key),
                    value=_encode_value(value),
                    unit_strindex=self.intern_string(unit),
                )
            )
        return self._attribute_indices[identity]

    def intern_link(self, trace_id: int, span_id: int) -> int:
        identity = (trace_id, span_id)
        if identity not in self._link_indices:
            self._link_indices[identity] = len(self._links)
            self._links.append(
                Link(
                    trace_id=_encode_trace_id(trace_id),
                    span_id=_encode_span_id(span_id),
                )
            )
        return self._link_indices[identity]

    def intern_stack(self, frames: tuple[CapturedFrame, ...]) -> int:
        location_indices = tuple(
            self._intern_location(frame) for frame in frames
        )
        if location_indices not in self._stack_indices:
            self._stack_indices[location_indices] = len(self._stacks)
            self._stacks.append(Stack(location_indices=location_indices))
        return self._stack_indices[location_indices]

    def _intern_location(self, frame: CapturedFrame) -> int:
        function_index = self._intern_function(frame)
        identity = (function_index, frame.lineno)
        if identity not in self._location_indices:
            self._location_indices[identity] = len(self._locations)
            self._locations.append(
                Location(
                    lines=[
                        Line(
                            function_index=function_index,
                            line=frame.lineno,
                        )
                    ]
                )
            )
        return self._location_indices[identity]

    def _intern_function(self, frame: CapturedFrame) -> int:
        identity = (
            frame.function,
            frame.function,
            frame.filename,
            0,
        )
        if identity not in self._function_indices:
            self._function_indices[identity] = len(self._functions)
            self._functions.append(
                Function(
                    name_strindex=self.intern_string(frame.function),
                    system_name_strindex=self.intern_string(frame.function),
                    filename_strindex=self.intern_string(frame.filename),
                    start_line=0,
                )
            )
        return self._function_indices[identity]
