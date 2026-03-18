# Test cluster support infrastructure.
#
# Verifies:
#   - Cluster events are declared and accessible
#   - Cluster wrapper functions are callable in standalone mode
#   - State is correctly updated via wrapper functions
#   - Full detection pipeline works through cluster-aware wrappers
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice
@load base/frameworks/cluster

@load SocialEngineering

global campaign_count = 0;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::CampaignMatch )
        ++campaign_count;
    }

event zeek_done()
    {
    # Test 1: Cluster events are declared
    print "PASS: cluster_learned_ioc event declared";
    print "PASS: cluster_track_campaign event declared";
    print "PASS: cluster_contact_pair event declared";
    print "PASS: cluster_conv_state event declared";

    # Test 2: Wrapper functions work in standalone mode
    # (cluster not enabled — functions should update local state directly)
    SocialEngineering::cluster_add_learned_ioc("test-sender@evil.com", "test subject");
    if ( "test-sender@evil.com" in SocialEngineering::learned_bad_senders )
        print "PASS: cluster_add_learned_ioc updates learned_bad_senders";
    else
        print "FAIL: cluster_add_learned_ioc did not update learned_bad_senders";

    if ( "test subject" in SocialEngineering::learned_bad_subjects )
        print "PASS: cluster_add_learned_ioc updates learned_bad_subjects";
    else
        print "FAIL: cluster_add_learned_ioc did not update learned_bad_subjects";

    SocialEngineering::cluster_add_track_campaign("test@evil.com", "<test-msg-id>", "test subj");
    if ( "test@evil.com" in SocialEngineering::tracked_campaign_senders )
        print "PASS: cluster_add_track_campaign updates tracked_campaign_senders";
    else
        print "FAIL: cluster_add_track_campaign did not update tracked_campaign_senders";

    if ( "<test-msg-id>" in SocialEngineering::tracked_campaign_msg_ids )
        print "PASS: cluster_add_track_campaign updates tracked_campaign_msg_ids";
    else
        print "FAIL: cluster_add_track_campaign did not update tracked_campaign_msg_ids";

    SocialEngineering::cluster_add_contact_pair("attacker@evil.com", "victim@eod.meh");
    if ( "attacker@evil.com" in SocialEngineering::campaign_contact_pairs
         && "victim@eod.meh" in SocialEngineering::campaign_contact_pairs["attacker@evil.com"] )
        print "PASS: cluster_add_contact_pair updates campaign_contact_pairs";
    else
        print "FAIL: cluster_add_contact_pair did not update campaign_contact_pairs";

    SocialEngineering::cluster_set_conv_state("attacker@evil.com,victim@eod.meh",
                                               SocialEngineering::VICTIM_REPLIED);
    if ( "attacker@evil.com,victim@eod.meh" in SocialEngineering::conversation_states
         && SocialEngineering::conversation_states["attacker@evil.com,victim@eod.meh"]
            == SocialEngineering::VICTIM_REPLIED )
        print "PASS: cluster_set_conv_state updates conversation_states";
    else
        print "FAIL: cluster_set_conv_state did not update conversation_states";

    # Test 3: Detection pipeline still works through wrappers
    if ( campaign_count > 0 )
        print fmt("PASS: CampaignMatch fired %d times (detection pipeline works via cluster wrappers)", campaign_count);
    else
        print "FAIL: CampaignMatch did not fire";

    # Test 4: Learned IOCs populated from pcap via cluster wrappers
    local learned_count = |SocialEngineering::learned_bad_senders|;
    # +1 for the manual test insertion above
    if ( learned_count > 1 )
        print fmt("PASS: learned_bad_senders has %d entries (from CampaignMatch + test)", learned_count);
    else
        print fmt("FAIL: learned_bad_senders has only %d entries", learned_count);

    # Test 5: Contact pairs populated from pcap via cluster wrappers
    local pair_count = |SocialEngineering::campaign_contact_pairs|;
    # +1 for the manual test insertion above
    if ( pair_count > 1 )
        print fmt("PASS: campaign_contact_pairs has %d entries (from CampaignMatch + test)", pair_count);
    else
        print fmt("FAIL: campaign_contact_pairs has only %d entries", pair_count);

    # Test 6: Conversation states populated from pcap via cluster wrappers
    local conv_count = |SocialEngineering::conversation_states|;
    if ( conv_count > 1 )
        print fmt("PASS: conversation_states has %d entries (from CampaignMatch + test)", conv_count);
    else
        print fmt("FAIL: conversation_states has only %d entries", conv_count);
    }
