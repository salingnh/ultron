"""The DNS wire helpers of the broker (G1.6 item 4): standard library only, no external resolver."""

from __future__ import annotations

import ipaddress
import struct

import pytest

from aegis.m06_runner import dns


def test_a_query_round_trips_through_parse_and_build() -> None:
    query = dns.build_query(0x1234, "bound.example", dns.TYPE_A)
    question = dns.parse_question(query)
    assert question.id == 0x1234
    assert question.name == "bound.example"
    assert question.qtype == dns.TYPE_A
    response = dns.build_response(question, ["198.51.100.7"])
    head = struct.unpack_from("!HHHHHH", response)
    assert head[0] == 0x1234
    assert head[1] & 0x8000 and head[1] & 0x0080  # QR + RA
    assert head[2] == 1 and head[3] == 1
    assert dns.parse_addresses(response) == ["198.51.100.7"]


def test_a_and_aaaa_answers_are_split_types() -> None:
    question = dns.parse_question(dns.build_query(1, "v6.example", dns.TYPE_AAAA))
    response = dns.build_response(question, ["2001:db8::7"])
    assert dns.parse_addresses(response) == ["2001:db8::7"]
    # The record type follows the address family, not the question type.
    mixed = dns.build_response(question, ["2001:db8::7", "198.51.100.7"])
    assert dns.parse_addresses(mixed) == ["2001:db8::7", "198.51.100.7"]


def test_an_error_response_carries_no_records() -> None:
    question = dns.parse_question(dns.build_query(7, "x.example", dns.TYPE_A))
    response = dns.build_response(question, [], rcode=dns.RCODE_REFUSED)
    _qid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", response)
    assert flags & 0x000F == dns.RCODE_REFUSED
    assert qd == 1 and an == 0
    assert dns.parse_addresses(response) == []


def test_compressed_owner_names_in_an_answer_are_skipped() -> None:
    # Answer section: name pointer -> question name, A record. Built by hand so the test does not
    # depend on the builder's own pointer form.
    question = dns.parse_question(dns.build_query(2, "c.example", dns.TYPE_A))
    record = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", dns.TYPE_A, dns.CLASS_IN, 30, 4)
        + bytes([203, 0, 113, 5])
    )
    message = struct.pack("!HHHHHH", 2, 0x8180, 1, 1, 0, 0) + question.section + record
    assert dns.parse_addresses(message) == ["203.0.113.5"]


def test_cname_chain_then_address_is_read() -> None:
    question = dns.parse_question(dns.build_query(3, "alias.example", dns.TYPE_A))
    cname_target = b"\x05bound\x07example\x00"
    cname = (
        b"\xc0\x0c" + struct.pack("!HHIH", 5, dns.CLASS_IN, 30, len(cname_target)) + cname_target
    )
    # Second record points at the CNAME target name inside the answer section (offset after header
    # + question + the first record).
    offset = 12 + len(question.section) + 12
    pointer = struct.pack("!H", 0xC000 | offset)
    a_record = (
        pointer + struct.pack("!HHIH", dns.TYPE_A, dns.CLASS_IN, 30, 4) + bytes([198, 51, 100, 9])
    )
    message = struct.pack("!HHHHHH", 3, 0x8180, 1, 2, 0, 0) + question.section + cname + a_record
    assert dns.parse_addresses(message) == ["198.51.100.9"]


@pytest.mark.parametrize(
    "message",
    [b"", b"\x00" * 11, struct.pack("!HHHHHH", 1, 0, 0, 0, 0, 0), b"\x00" * 12 + b"\x09example"],
)
def test_malformed_queries_are_rejected(message: bytes) -> None:
    with pytest.raises(ValueError):
        dns.parse_question(message)


def test_a_bad_label_length_is_rejected() -> None:
    message = (
        struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        + b"\x40"
        + b"x" * 40
        + b"\x00\x00\x01\x00\x01"
    )
    with pytest.raises(ValueError):
        dns.parse_question(message)


def test_a_query_builder_encodes_idna() -> None:
    # A Unicode target is put on the wire as IDNA; the parsed name is the ASCII form the canonical
    # keys use (`dns:xn--...`), which is exactly what the policy binds.
    query = dns.build_query(9, "tên.example", dns.TYPE_A)
    question = dns.parse_question(query)
    assert question.name == "xn--tn-eja.example"
    assert ipaddress.ip_address("198.51.100.7")
