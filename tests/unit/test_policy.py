import pytest
from helpers import (
    NoHosts,
    StaticHosts,
    a,
    aaaa,
    instance_name,
    meta_ptr,
    n,
    ptr,
    query,
    response,
    rule,
    srv,
    txt,
    type_name,
)

from mdns_relay.policy import filter_ssdp
from mdns_relay.ssdp import KIND_NOTIFY, KIND_SEARCH, SsdpMessage
from mdns_relay.dns import (
    META_QUERY_NAME,
    TYPE_A,
    TYPE_AAAA,
    TYPE_NSEC,
    TYPE_PTR,
    TYPE_SRV,
    TYPE_TXT,
    Message,
    NsecData,
    Question,
    Record,
)
from mdns_relay.policy import (
    DROP_LINK_LOCAL,
    DROP_NON_LOCAL,
    REASON_NO_RULE,
    REASON_NOTHING_PERMITTED,
    REASON_PROBE,
    filter_packet,
)

HTTP = "_http._tcp"
IPP = "_ipp._tcp"


def forward(message, rules, hosts=None):
    """Filter a message on the direction that its kind would use under a rule."""
    source, destination = ("prov", "cli") if message.is_response else ("cli", "prov")
    return filter_packet(message, source, destination, rules, hosts or NoHosts())


def full_response():
    return response(
        [ptr(HTTP, "Web"), meta_ptr(HTTP)],
        [srv(HTTP, "Web", "host.local"), txt(HTTP, "Web", "a=1"), a("host.local", "192.0.2.1")],
    )


# --- Default deny ---


@pytest.mark.parametrize(
    "message",
    [
        full_response(),
        query(Question(type_name(HTTP), TYPE_PTR)),
        query(Question(META_QUERY_NAME, TYPE_PTR)),
    ],
)
def test_no_rules_relays_nothing(message):
    decision = forward(message, [])
    assert decision.message is None
    assert decision.reason == REASON_NO_RULE


@pytest.mark.parametrize(
    "bad_rule",
    [
        rule(enabled=False),
        rule(provider="other"),
        rule(client="other"),
        rule(provider="cli", client="prov"),
    ],
)
def test_rule_for_another_path_relays_nothing(bad_rule):
    decision = forward(full_response(), [bad_rule])
    assert decision.message is None
    assert decision.reason == REASON_NO_RULE


def test_rule_is_one_way():
    rules = [rule()]
    # Client-side services aren't sent to the provider.
    assert filter_packet(full_response(), "cli", "prov", rules, NoHosts()).message is None
    # Provider-side queries aren't sent to the client.
    q = query(Question(type_name(HTTP), TYPE_PTR))
    assert filter_packet(q, "prov", "cli", rules, NoHosts()).message is None


def test_rule_of_another_type_relays_nothing():
    decision = forward(full_response(), [rule(IPP)])
    assert decision.message is None
    assert decision.reason == REASON_NOTHING_PERMITTED


# --- Questions ---


@pytest.mark.parametrize(
    "question,rules,hosts,allowed",
    [
        # PTR for the type
        (Question(type_name(HTTP), TYPE_PTR), [rule()], None, True),
        (Question(type_name(IPP), TYPE_PTR), [rule()], None, False),
        (Question(type_name(HTTP), TYPE_TXT), [rule()], None, False),
        # Subtypes
        (Question(n("_printer._sub._http._tcp.local"), TYPE_PTR), [rule()], None, True),
        (Question(n("_printer._sub._ipp._tcp.local"), TYPE_PTR), [rule()], None, False),
        # Instance questions honour the pattern
        (Question(instance_name("Web", HTTP), TYPE_SRV), [rule()], None, True),
        (Question(instance_name("Web", HTTP), TYPE_TXT), [rule()], None, True),
        (Question(instance_name("Web", HTTP), 255), [rule()], None, True),
        (Question(instance_name("Web", HTTP), TYPE_A), [rule()], None, False),
        (Question(instance_name("Web", HTTP), TYPE_SRV), [rule(instance_pattern="Oth*")], None, False),
        # Meta query needs a rule on the path, which any applicable rule provides
        (Question(META_QUERY_NAME, TYPE_PTR), [rule()], None, True),
        (Question(META_QUERY_NAME, TYPE_TXT), [rule()], None, False),
        # Host questions need a permitted instance on the provider
        (Question(n("host.local"), TYPE_A), [rule()], None, False),
        (
            Question(n("host.local"), TYPE_A),
            [rule()],
            {("prov", n("host.local")): [(HTTP, "Web")]},
            True,
        ),
        (
            Question(n("host.local"), TYPE_AAAA),
            [rule()],
            {("prov", n("host.local")): [(HTTP, "Web")]},
            True,
        ),
        (
            Question(n("host.local"), TYPE_A),
            [rule()],
            {("prov", n("host.local")): [(IPP, "Printer")]},
            False,
        ),
        (
            Question(n("host.local"), TYPE_A),
            [rule(instance_pattern="Oth*")],
            {("prov", n("host.local")): [(HTTP, "Web")]},
            False,
        ),
        # Learned on a different interface doesn't count
        (
            Question(n("host.local"), TYPE_A),
            [rule()],
            {("other", n("host.local")): [(HTTP, "Web")]},
            False,
        ),
        # Other names
        (Question(n("host.example.com"), TYPE_A), [rule()], None, False),
        (Question(n("1.2.0.192.in-addr.arpa"), TYPE_PTR), [rule()], None, False),
        (Question(type_name(HTTP), TYPE_PTR, qclass=3), [rule()], None, False),
    ],
)
def test_question_filter(question, rules, hosts, allowed):
    decision = forward(query(question), rules, StaticHosts(hosts) if hosts else None)
    assert (decision.message is not None) == allowed


def test_query_keeps_only_permitted_questions():
    decision = forward(
        query(Question(type_name(HTTP), TYPE_PTR), Question(type_name(IPP), TYPE_PTR)),
        [rule()],
    )
    assert [q.name for q in decision.message.questions] == [type_name(HTTP)]


def test_qu_bit_is_cleared():
    decision = forward(query(Question(type_name(HTTP), TYPE_PTR, unicast=True)), [rule()])
    assert decision.message.questions[0].unicast is False


def test_probe_is_never_relayed():
    message = query(Question(instance_name("Web", HTTP), 255))
    message.authorities.append(srv(HTTP, "Web", "host.local"))
    decision = forward(message, [rule()])
    assert decision.message is None
    assert decision.reason == REASON_PROBE


def test_known_answers_are_filtered():
    decision = forward(
        query(
            Question(type_name(HTTP), TYPE_PTR),
            known=[ptr(HTTP, "Web"), ptr(IPP, "Printer"), a("x.local", "192.0.2.5")],
        ),
        [rule()],
    )
    assert decision.message.answers == [ptr(HTTP, "Web")]


def test_known_answers_alone_relayed_only_as_a_continuation():
    # All questions filtered out: permitted known answers must not go on their own.
    filtered = query(Question(type_name(IPP), TYPE_PTR), known=[ptr(HTTP, "Web")])
    assert forward(filtered, [rule()]).message is None
    # No questions to begin with: a truncated query's continuation packet.
    continuation = query(known=[ptr(HTTP, "Web")])
    assert forward(continuation, [rule()]).message.answers == [ptr(HTTP, "Web")]
    assert forward(query(), [rule()]).message is None


def test_srv_in_a_query_cannot_grant_access_to_a_host():
    message = query(
        Question(n("secret.local"), TYPE_A),
        known=[srv(HTTP, "Web", "secret.local")],
    )
    assert forward(message, [rule()]).message is None


def test_query_additional_and_authority_sections_are_not_relayed():
    message = query(Question(type_name(HTTP), TYPE_PTR))
    message.additionals.append(ptr(HTTP, "Web"))
    decision = forward(message, [rule()])
    assert decision.message.additionals == []
    assert decision.message.authorities == []


# --- Response records ---


def test_full_response_passes_when_permitted():
    message = full_response()
    decision = forward(message, [rule()])
    assert decision.message.answers == message.answers
    assert decision.message.additionals == message.additionals
    assert decision.message.flags == message.flags


def test_unrelated_service_in_same_packet_is_removed():
    decision = forward(
        response(
            [ptr(HTTP, "Web"), ptr(IPP, "Printer")],
            [
                srv(HTTP, "Web", "webhost.local"),
                srv(IPP, "Printer", "printhost.local"),
                txt(IPP, "Printer", "secret=1"),
                a("webhost.local", "192.0.2.1"),
                a("printhost.local", "192.0.2.2"),
            ],
        ),
        [rule()],
    )
    assert decision.message.answers == [ptr(HTTP, "Web")]
    assert decision.message.additionals == [
        srv(HTTP, "Web", "webhost.local"),
        a("webhost.local", "192.0.2.1"),
    ]


def test_instance_pattern_filters_instances_case_insensitively():
    decision = forward(
        response([ptr(HTTP, "Living Room"), ptr(HTTP, "Kitchen")]),
        [rule(instance_pattern="living*")],
    )
    assert decision.message.answers == [ptr(HTTP, "Living Room")]


def test_type_comparison_is_case_insensitive():
    upper = Record(type_name("_HTTP._TCP"), TYPE_PTR, 120, instance_name("Web", "_HTTP._TCP"))
    assert forward(response([upper]), [rule()]).message is not None


def test_wildcard_rule_must_be_explicit_and_matches_any_type():
    decision = forward(response([ptr(HTTP, "Web"), ptr(IPP, "Printer")]), [rule("*")])
    assert len(decision.message.answers) == 2


def test_meta_ptr_only_for_permitted_types():
    decision = forward(response([meta_ptr(HTTP), meta_ptr(IPP)]), [rule()])
    assert decision.message.answers == [meta_ptr(HTTP)]


def test_ptr_cannot_smuggle_another_type():
    record = Record(type_name(HTTP), TYPE_PTR, 120, instance_name("Printer", IPP))
    assert forward(response([record]), [rule()]).message is None


def test_subtype_ptr_is_permitted():
    record = Record(
        n("_printer._sub._http._tcp.local"), TYPE_PTR, 120, instance_name("Web", HTTP)
    )
    assert forward(response([record]), [rule()]).message.answers == [record]


def test_nsec_follows_its_owner():
    nsec_ok = Record(instance_name("Web", HTTP), TYPE_NSEC, 120, NsecData(n("x.local"), b""))
    nsec_no = Record(instance_name("P", IPP), TYPE_NSEC, 120, NsecData(n("x.local"), b""))
    decision = forward(response([nsec_ok, nsec_no]), [rule()])
    assert decision.message.answers == [nsec_ok]


def test_address_permitted_by_srv_in_same_packet():
    decision = forward(
        response([srv(HTTP, "Web", "h.local")], [a("h.local", "192.0.2.1")]), [rule()]
    )
    assert decision.message.additionals == [a("h.local", "192.0.2.1")]


def test_address_permitted_by_learned_srv():
    hosts = StaticHosts({("prov", n("h.local")): [(HTTP, "Web")]})
    decision = forward(response([a("h.local", "192.0.2.1")]), [rule()], hosts)
    assert decision.message.answers == [a("h.local", "192.0.2.1")]


def test_address_of_unknown_host_is_removed():
    assert forward(response([a("h.local", "192.0.2.1")]), [rule()]).message is None


def test_address_of_host_for_a_forbidden_instance_is_removed():
    decision = forward(
        response([srv(HTTP, "Secret", "h.local")], [a("h.local", "192.0.2.1")]),
        [rule(instance_pattern="Web*")],
    )
    assert decision.message is None


@pytest.mark.parametrize(
    "record",
    [a("h.local", "169.254.1.1"), aaaa("h.local", "fe80::1")],
)
def test_link_local_addresses_are_removed(record):
    decision = forward(
        response([srv(HTTP, "Web", "h.local")], [record, a("h.local", "192.0.2.1")]), [rule()]
    )
    assert decision.message.additionals == [a("h.local", "192.0.2.1")]
    assert decision.dropped[DROP_LINK_LOCAL] == 1


def test_routable_ipv6_is_kept():
    record = aaaa("h.local", "2001:db8::1")
    decision = forward(response([srv(HTTP, "Web", "h.local")], [record]), [rule()])
    assert decision.message.additionals == [record]


def test_non_local_records_are_removed():
    reverse = Record(n("1.2.0.192.in-addr.arpa"), TYPE_PTR, 120, n("h.local"))
    other = Record(n("www.example.com"), TYPE_A, 120, b"\xc0\x00\x02\x01")
    decision = forward(response([ptr(HTTP, "Web"), reverse, other]), [rule()])
    assert decision.message.answers == [ptr(HTTP, "Web")]
    assert decision.dropped[DROP_NON_LOCAL] == 2


def test_response_with_only_additionals_left_is_dropped():
    decision = forward(
        response([ptr(IPP, "Printer")], [srv(HTTP, "Web", "h.local")]), [rule()]
    )
    assert decision.message is None


def test_response_authority_section_is_removed():
    message = response([ptr(HTTP, "Web")])
    message.authorities.append(ptr(HTTP, "Web"))
    assert forward(message, [rule()]).message.authorities == []


def test_goodbye_ttl_and_cache_flush_preserved():
    record = Record(
        instance_name("Web", HTTP), TYPE_TXT, 0, b"\0", cache_flush=True
    )
    decision = forward(response([record]), [rule()])
    assert decision.message.answers[0].ttl == 0
    assert decision.message.answers[0].cache_flush is True


def test_rule_ids_are_reported():
    permitted = rule()
    decision = forward(response([ptr(HTTP, "Web")]), [rule(IPP), permitted])
    assert decision.rule_ids == {permitted.id}


def test_input_message_is_not_modified():
    message = query(Question(type_name(HTTP), TYPE_PTR, unicast=True))
    forward(message, [rule()])
    assert message.questions[0].unicast is True


def test_ssdp_rule_never_authorizes_mdns():
    ssdp_rule = rule(service_type="*", protocol="ssdp")
    decision = filter_packet(response([ptr("_http._tcp", "A")]), "prov", "cli", [ssdp_rule], NoHosts())
    assert decision.message is None
    assert decision.reason == REASON_NO_RULE


def test_mdns_rule_never_authorizes_ssdp():
    notify = SsdpMessage(KIND_NOTIFY, "upnp:rootdevice", usn="uuid:a")
    decision = filter_ssdp(notify, "prov", "cli", [rule(service_type="*")])
    assert decision.message is None
    assert decision.reason == REASON_NO_RULE


def test_ssdp_all_search_passes_with_any_rule_and_typed_search_needs_match():
    typed = rule(service_type="urn:x:device:Tv:1", protocol="ssdp")
    assert filter_ssdp(SsdpMessage(KIND_SEARCH, "ssdp:all"), "cli", "prov", [typed]).message
    assert filter_ssdp(SsdpMessage(KIND_SEARCH, "urn:x:device:Tv:1"), "cli", "prov", [typed]).message
    other = filter_ssdp(SsdpMessage(KIND_SEARCH, "upnp:rootdevice"), "cli", "prov", [typed])
    assert other.message is None
    assert other.reason == "nothing_permitted"


def test_ssdp_usn_pattern_filters_and_direction_is_one_way():
    typed = rule(service_type="*", protocol="ssdp", instance_pattern="uuid:good*")
    good = SsdpMessage(KIND_NOTIFY, "upnp:rootdevice", usn="uuid:good-1")
    bad = SsdpMessage(KIND_NOTIFY, "upnp:rootdevice", usn="uuid:bad-1")
    assert filter_ssdp(good, "prov", "cli", [typed]).message
    assert filter_ssdp(bad, "prov", "cli", [typed]).message is None
    assert filter_ssdp(good, "cli", "prov", [typed]).reason == REASON_NO_RULE
