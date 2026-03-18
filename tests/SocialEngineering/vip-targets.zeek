# Test high-value target escalation.
#
# Verifies:
#   - VIPTargeted notice fires when campaign email targets a configured VIP
#   - VIPTargeted notice includes ACTION_EMAIL
#   - Non-VIP recipients don't trigger VIPTargeted
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

# Configure one recipient as a VIP
redef SocialEngineering::high_value_targets += {
    "user1xxx@eod.meh",
};

global vip_count = 0;
global campaign_count = 0;
global vip_has_email_action = F;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::VIPTargeted )
        {
        ++vip_count;
        if ( Notice::ACTION_EMAIL in n$actions )
            vip_has_email_action = T;
        }
    if ( n$note == SocialEngineering::CampaignMatch )
        ++campaign_count;
    }

event zeek_done()
    {
    print fmt("CampaignMatch notices: %d", campaign_count);
    print fmt("VIPTargeted notices: %d", vip_count);

    if ( vip_count > 0 )
        print "PASS: VIPTargeted fired for configured VIP recipient";
    else
        print "FAIL: VIPTargeted never fired";

    # Should be exactly 1 — only user1xxx@eod.meh is a VIP
    if ( vip_count == 1 )
        print "PASS: VIPTargeted fired exactly once (only one VIP in recipient list)";
    else
        print fmt("INFO: VIPTargeted fired %d times (expected 1)", vip_count);

    if ( vip_has_email_action )
        print "PASS: VIPTargeted includes ACTION_EMAIL";
    else
        print "FAIL: VIPTargeted missing ACTION_EMAIL";
    }
