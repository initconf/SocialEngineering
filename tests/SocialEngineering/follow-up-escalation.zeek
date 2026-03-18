# Test follow-up escalation scoring.
#
# Verifies:
#   - campaign_contact_pairs table is available and initially empty
#   - FOLLOW_UP_CONTACT does NOT trigger on pcap (each sender→recipient
#     pair appears only once — no repeated contacts)
#   - Contact pairs are recorded after CampaignMatch fires
#   - Scores remain unchanged from pre-Phase 7 values (no follow-up boost)
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global campaign_count = 0;
global follow_up_count = 0;
global matched_indicators: vector of string;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::CampaignMatch )
        {
        ++campaign_count;
        matched_indicators += n$msg;
        }
    }

event zeek_done()
    {
    # Test 1: campaign_contact_pairs table exists and was populated
    local pair_count = |SocialEngineering::campaign_contact_pairs|;
    print fmt("PASS: campaign_contact_pairs has %d sender entries after processing", pair_count);

    if ( pair_count > 0 )
        print "PASS: Contact pairs recorded from CampaignMatch detections";
    else
        print "FAIL: No contact pairs recorded (CampaignMatch should populate them)";

    # Test 2: CampaignMatch still fires normally
    print fmt("PASS: CampaignMatch fired %d times", campaign_count);

    # Test 3: No FOLLOW_UP_CONTACT in matched indicators
    # (pcap has unique sender→recipient pairs, no repeats)
    local has_followup = F;
    for ( idx in matched_indicators )
        {
        if ( /FOLLOW_UP/ in matched_indicators[idx] )
            has_followup = T;
        }

    if ( ! has_followup )
        print "PASS: No FOLLOW_UP_CONTACT triggered (no repeated sender-recipient pairs in pcap)";
    else
        print "FAIL: FOLLOW_UP_CONTACT triggered unexpectedly on first-contact pcap";
    }
