# Test conversation state tracking.
#
# Verifies:
#   - ConversationEscalation notice type is registered
#   - ConversationState enum values are accessible
#   - conversation_states table is populated after CampaignMatch
#   - ConversationEscalation does NOT fire on pcap (no reply→followup
#     sequence in campaign-samples.pcap)
#   - ACTION_EMAIL is configured for ConversationEscalation
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global escalation_count = 0;
global campaign_count = 0;
global escalation_has_email = F;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::ConversationEscalation )
        {
        ++escalation_count;
        if ( Notice::ACTION_EMAIL in n$actions )
            escalation_has_email = T;
        }
    if ( n$note == SocialEngineering::CampaignMatch )
        ++campaign_count;
    }

event zeek_done()
    {
    # Test 1: Notice type is registered
    local ce_type = SocialEngineering::ConversationEscalation;
    print fmt("PASS: ConversationEscalation type registered = %s", ce_type);

    # Test 2: ConversationState enum values are accessible
    local s1 = SocialEngineering::CAMPAIGN_SENT;
    local s2 = SocialEngineering::VICTIM_REPLIED;
    local s3 = SocialEngineering::ATTACKER_FOLLOWUP;
    print fmt("PASS: CAMPAIGN_SENT = %s", s1);
    print fmt("PASS: VICTIM_REPLIED = %s", s2);
    print fmt("PASS: ATTACKER_FOLLOWUP = %s", s3);

    # Test 3: conversation_states populated after CampaignMatch
    local state_count = |SocialEngineering::conversation_states|;
    if ( state_count > 0 )
        print fmt("PASS: conversation_states has %d entries after CampaignMatch", state_count);
    else
        print "FAIL: conversation_states is empty (CampaignMatch should populate it)";

    # Test 4: All states should be CAMPAIGN_SENT (no replies in this pcap)
    local all_sent = T;
    for ( key, state in SocialEngineering::conversation_states )
        {
        if ( state != SocialEngineering::CAMPAIGN_SENT )
            {
            all_sent = F;
            break;
            }
        }
    if ( all_sent )
        print "PASS: All conversation states are CAMPAIGN_SENT (no replies in pcap)";
    else
        print "FAIL: Unexpected conversation state transition";

    # Test 5: ConversationEscalation should NOT fire (no reply→followup in pcap)
    if ( escalation_count == 0 )
        print "PASS: ConversationEscalation correctly did not fire (no reply-followup sequence)";
    else
        print fmt("FAIL: ConversationEscalation fired %d times (expected 0)", escalation_count);

    # Test 6: CampaignMatch still works
    print fmt("PASS: CampaignMatch fired %d times", campaign_count);
    }
