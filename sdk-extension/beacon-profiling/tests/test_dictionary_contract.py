from __future__ import annotations

import pytest

from opentelemetry.proto.collector.profiles.v1development.profiles_service_pb2 import (
    ExportProfilesServiceRequest,
)
from opentelemetry.sdk.extension.profiling.collector.base import (
    CapturedAttribute,
    CapturedFrame,
    CapturedSample,
)
from opentelemetry.sdk.extension.profiling.model.builder import (
    ProfilesRequestBuilder,
)
from opentelemetry.sdk.resources import Resource


@pytest.mark.parametrize("count", [0, 1, 3])
def test_dictionary_zero_values_and_references_round_trip(count: int) -> None:
    frames = (CapturedFrame("business", "/app/business.py", 42),)
    samples = [
        CapturedSample(
            timestamp_unix_nano=100 + index,
            thread_id=1,
            thread_name="worker",
            frames=frames,
            trace_id=123,
            span_id=456,
            attributes=(CapturedAttribute("custom", "value"),),
        )
        for index in range(count)
    ]
    request = ProfilesRequestBuilder().build(
        samples, Resource.create({"service.name": "test"}), 10
    )
    decoded = ExportProfilesServiceRequest.FromString(
        request.SerializeToString()
    )
    dictionary = decoded.dictionary
    assert dictionary.string_table[0] == ""
    for name in (
        "mapping_table",
        "location_table",
        "function_table",
        "link_table",
        "attribute_table",
        "stack_table",
    ):
        table = getattr(dictionary, name)
        assert len(table) >= 1
        assert not table[0].ListFields(), name
    if not count:
        return

    profile = decoded.resource_profiles[0].scope_profiles[0].profiles[0]
    assert len(profile.samples) == 1
    sample = profile.samples[0]
    assert list(sample.timestamps_unix_nano) == list(range(100, 100 + count))
    assert list(sample.values) == [1] * count
    assert 0 < sample.stack_index < len(dictionary.stack_table)
    stack = dictionary.stack_table[sample.stack_index]
    assert len(stack.location_indices) == 1
    location_index = stack.location_indices[0]
    assert 0 < location_index < len(dictionary.location_table)
    location = dictionary.location_table[location_index]
    assert location.mapping_index == 0
    function_index = location.lines[0].function_index
    assert 0 < function_index < len(dictionary.function_table)
    function = dictionary.function_table[function_index]
    assert dictionary.string_table[function.name_strindex] == "business"
    assert dictionary.string_table[function.filename_strindex] == (
        "/app/business.py"
    )
    assert 0 < sample.link_index < len(dictionary.link_table)
    link = dictionary.link_table[sample.link_index]
    assert link.span_id == (456).to_bytes(8, "big")
    assert sample.attribute_indices
    assert all(
        0 < index < len(dictionary.attribute_table)
        for index in sample.attribute_indices
    )
    assert len(dictionary.function_table) == 2
    assert len(dictionary.stack_table) == 2


def test_empty_stack_uses_reserved_zero_entry() -> None:
    sample = CapturedSample(100, 1, "worker", ())
    request = ProfilesRequestBuilder().build([sample], Resource.create(), 10)
    profile = request.resource_profiles[0].scope_profiles[0].profiles[0]
    assert profile.samples[0].stack_index == 0
    assert len(request.dictionary.stack_table) == 1
