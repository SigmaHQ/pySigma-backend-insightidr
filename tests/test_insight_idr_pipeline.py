import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.backends.insight_idr import InsightIDRBackend


def test_insight_idr_pipeline_simple():
    assert (
        InsightIDRBackend().convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: val1
                    Image: val2
                condition: sel
        """
            )
        )
        == ['process.cmd_line = NOCASE("val1") AND process.exe_path = NOCASE("val2")']
    )


def test_insight_idr_pipeline_process_creation_field_mapping():
    assert (
        InsightIDRBackend().convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    ProcessId: 1962
                    Image: 'Paint it Black'
                    FileVersion: 'Gimme Shelter'
                    Description: 'Sympathy for the Devil'
                    Product: 'Under my Thumb'
                    Company: "She's a Rainbow"
                    OriginalFileName: 'Wild Horses'
                    CommandLine: "Jumpin' Jack Flash"
                    User: 'Mick Jagger'
                    ParentProcessId: 1972
                    ParentImage: 'Muddy Waters'
                    ParentCommandLine: 'Start Me Up'
                    ParentUser: 'Charlie Watts'
                    md5: 'Steel Wheels'
                    sha1: 'Beggars Banquet'
                    sha256: 'Let it Bleed'
                condition: sel
        """
            )
        )
        == [
            'process.pid=1962 AND process.exe_path = NOCASE("Paint it Black") AND process.exe_file.version = NOCASE("Gimme Shelter") \
AND process.exe_file.description = NOCASE("Sympathy for the Devil") AND process.exe_file.product_name = NOCASE("Under my Thumb") \
AND process.exe_file.author = NOCASE("""She\'s a Rainbow""") AND process.name = NOCASE("Wild Horses") \
AND process.cmd_line = NOCASE("""Jumpin\' Jack Flash""") AND process.username = NOCASE("Mick Jagger") AND parent_process.pid=1972 \
AND parent_process.exe_path = NOCASE("Muddy Waters") AND parent_process.cmd_line = NOCASE("Start Me Up") \
AND parent_process.username = NOCASE("Charlie Watts") AND process.exe_file.hashes.md5 = NOCASE("Steel Wheels") \
AND process.exe_file.hashes.sha1 = NOCASE("Beggars Banquet") AND process.exe_file.hashes.sha256 = NOCASE("Let it Bleed")'
        ]
    )


def test_insight_idr_pipeline_dns_field_mapping():
    assert (
        InsightIDRBackend().convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: dns
            detection:
                sel:
                    QueryName: 'My Generation'
                    Computer: 'Teenage Wasteland'
                    record_type: 'Pinball Wizard'
                condition: sel
        """
            )
        )
        == [
            'query = NOCASE("My Generation") AND asset = NOCASE("Teenage Wasteland") AND query_type = NOCASE("Pinball Wizard")'
        ]
    )


def test_insight_idr_pipeline_web_proxy_field_mapping():
    assert (
        InsightIDRBackend().convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: proxy
            detection:
                sel:
                    c-uri: 'https://www.thebeatles.com/'
                    c-uri-query: 'songs'
                    cs-bytes: 100
                    cs-host: 'www.thebeatles.com'
                    cs-method: GET
                    r-dns: 'www.thebeatles.com'
                    sc-bytes: 500
                    src_ip|cidr: 192.168.1.0/24
                    dst_ip: '54.229.169.162'
                condition: sel
        """
            )
        )
        == [
            'url = NOCASE("https://www.thebeatles.com/") AND url_path = NOCASE("songs") AND incoming_bytes=100 \
AND url_host = NOCASE("www.thebeatles.com") AND http_method = NOCASE("GET") AND url_host = NOCASE("www.thebeatles.com") \
AND outgoing_bytes=500 AND source_ip = IP(192.168.1.0/24) AND destination_ip = NOCASE("54.229.169.162")'
        ]
    )


def test_insight_idr_pipeline_unsupported_field_process_start():
    with pytest.raises(
        SigmaTransformationError,
        match="The InsightIDR backend does not support the CurrentDirectory, IntegrityLevel, or imphash fields for process start rules.",
    ):
        InsightIDRBackend().convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        CurrentDirectory|contains: hi
                        IntegrityLevel: hello
                        imphash: blah
                    condition: sel
            """
            )
        )


def test_insight_idr_pipeline_unsupported_field_dns():
    with pytest.raises(
        SigmaTransformationError,
        match="The InsightIDR backend does not support the ProcessID, QueryStatus, QueryResults, Image, or answer fields for DNS events.",
    ):
        InsightIDRBackend().convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: dns
                detection:
                    sel:
                        ProcessId: 1
                    condition: sel
            """
            )
        )


def test_insight_idr_pipeline_unsupported_field_web_proxy():
    with pytest.raises(
        SigmaTransformationError,
        match="The InsightIDR backend does not support the c-uri-extension, c-uri-stem, c-useragent, cs-cookie, cs-referrer, cs-version, or sc-status fields for web proxy events.",
    ):
        InsightIDRBackend().convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: proxy
                detection:
                    sel:
                        c-uri-extension: test
                    condition: sel
            """
            )
        )


def test_insight_idr_pipeline_unsupported_rule_type():
    with pytest.raises(
        SigmaTransformationError,
        match="Rule type not yet supported by the InsightIDR Sigma backend!",
    ):
        InsightIDRBackend().convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: novel_category
                detection:
                    sel:
                        field: blah
                    condition: sel
            """
            )
        )


def test_insight_idr_pipeline_unsupported_aggregate_conditions_rule_type():
    with pytest.raises(
        SigmaTransformationError,
        match="Rules with aggregate function conditions like count, min, max, avg, sum, and near are not supported by the InsightIDR Sigma backend!",
    ):
        InsightIDRBackend().convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: dns
                detection:
                    sel:
                        field: blah
                    condition: sel | count() > 10
            """
            )
        )
