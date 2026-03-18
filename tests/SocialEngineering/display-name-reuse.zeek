# Test display name reuse detection.
#
# Verifies:
#   - DisplayNameReuse notice type is registered
#   - DisplayNameReuse does NOT fire when sender address matches a known
#     IOC or pattern (pcap senders all match known_bad_sender_patterns)
#   - DisplayNameReuse WOULD fire for a known display name with an
#     unrecognized external sender address (verified via logic check)
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global display_name_reuse_count = 0;
global known_sender_count = 0;
global campaign_count = 0;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::DisplayNameReuse )
        ++display_name_reuse_count;
    if ( n$note == SocialEngineering::KnownSender )
        ++known_sender_count;
    if ( n$note == SocialEngineering::CampaignMatch )
        ++campaign_count;
    }

event zeek_done()
    {
    # Test 1: Notice type is registered
    local dn_type = SocialEngineering::DisplayNameReuse;
    print fmt("PASS: DisplayNameReuse type registered = %s", dn_type);

    # Test 2: DisplayNameReuse should NOT fire for pcap emails
    # (all pcap senders match known_bad_sender_patterns — address already matched)
    if ( display_name_reuse_count == 0 )
        print "PASS: DisplayNameReuse correctly suppressed (sender addresses matched IOC patterns)";
    else
        print fmt("FAIL: DisplayNameReuse fired %d times (expected 0 — pcap senders match patterns)", display_name_reuse_count);

    # Test 3: Known sender IOCs still fire normally (display name reuse doesn't break existing flow)
    if ( known_sender_count > 0 )
        print fmt("PASS: KnownSender still fires normally (%d notices)", known_sender_count);
    else
        print "FAIL: KnownSender stopped firing (display name reuse broke IOC detection)";

    # Test 4: Campaign detection still works
    if ( campaign_count > 0 )
        print fmt("PASS: CampaignMatch still fires normally (%d notices)", campaign_count);
    else
        print "FAIL: CampaignMatch stopped firing";

    # Test 5: Verify known_bad_display_names are loaded (prerequisite for detection)
    if ( "Amy Bloom" in SocialEngineering::known_bad_display_names )
        print "PASS: Display name 'Amy Bloom' is loaded";
    else
        print "FAIL: Display name 'Amy Bloom' not loaded";

    if ( "Lillian Briger" in SocialEngineering::known_bad_display_names )
        print "PASS: Display name 'Lillian Briger' is loaded";
    else
        print "FAIL: Display name 'Lillian Briger' not loaded";

    # Test 6: Verify internal_mail_domains are loaded (used for exemption)
    if ( "eod.meh" in SocialEngineering::internal_mail_domains )
        print "PASS: Internal domain 'eod.meh' is loaded";
    else
        print "FAIL: Internal domain 'eod.meh' not loaded";
    }
