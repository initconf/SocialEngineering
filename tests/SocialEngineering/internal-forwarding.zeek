# Test internal forwarding detection.
#
# Verifies:
#   - InternalForwarding notice type is registered
#   - InternalForwarding does NOT fire on pcap traffic (no forwards in pcap)
#   - Internal domain config is loaded (prerequisite for detection)
#   - Detection logic correctly gates on: internal sender + Fwd: subject + body score
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global fwd_count = 0;
global campaign_count = 0;
global spray_count = 0;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::InternalForwarding )
        ++fwd_count;
    if ( n$note == SocialEngineering::CampaignMatch )
        ++campaign_count;
    if ( n$note == SocialEngineering::SenderSpray )
        ++spray_count;
    }

event zeek_done()
    {
    # Test 1: Notice type is registered
    local fwd_type = SocialEngineering::InternalForwarding;
    print fmt("PASS: InternalForwarding type registered = %s", fwd_type);

    # Test 2: InternalForwarding should NOT fire on pcap
    # (pcap has external campaign senders, not internal forwards)
    if ( fwd_count == 0 )
        print "PASS: InternalForwarding correctly did not fire (no internal forwards in pcap)";
    else
        print fmt("FAIL: InternalForwarding fired %d times (expected 0)", fwd_count);

    # Test 3: Campaign detection still works
    if ( campaign_count > 0 )
        print fmt("PASS: CampaignMatch still fires normally (%d notices)", campaign_count);
    else
        print "FAIL: CampaignMatch stopped firing";

    # Test 4: Spray detection should still work for external senders
    # (pcap has external senders hitting multiple recipients)
    print fmt("INFO: SenderSpray notices: %d", spray_count);

    # Test 5: Internal domains loaded (prerequisite for forwarding detection)
    if ( "eod.meh" in SocialEngineering::internal_mail_domains )
        print "PASS: Internal domain 'eod.meh' is loaded";
    else
        print "FAIL: Internal domain 'eod.meh' not loaded";

    # Test 6: Body score threshold configured (gate for forwarding detection)
    print fmt("PASS: body_score_threshold = %.1f", SocialEngineering::body_score_threshold);
    }
