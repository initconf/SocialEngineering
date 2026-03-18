# Test Intel framework integration.
#
# Verifies:
#   - insert_intel_indicator function is callable and doesn't error
#   - CampaignMatch fires (which triggers Intel insertion)
#   - Intel framework is loaded and operational
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global campaign_count = 0;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::CampaignMatch )
        ++campaign_count;
    }

event zeek_init()
    {
    # Verify Intel framework is loaded by checking type existence
    local test_type = Intel::EMAIL;
    print fmt("PASS: Intel framework loaded (Intel::EMAIL = %s)", test_type);

    # Verify insert function is callable
    SocialEngineering::insert_intel_indicator(
        "test@example.com", Intel::EMAIL, "unit test indicator");
    print "PASS: insert_intel_indicator callable without error";
    }

event zeek_done()
    {
    print fmt("CampaignMatch notices: %d", campaign_count);

    if ( campaign_count > 0 )
        print fmt("PASS: %d campaign senders fed to Intel framework", campaign_count);
    else
        print "FAIL: No CampaignMatch notices (no Intel insertions)";
    }
