# Test the full attacker-victim conversation lifecycle using conversation.pcap.
#
# This pcap contains a real multi-stage email exchange between a Lillian Briger
# campaign sender and an internal user (jcemerald@eod.meh), including:
#   1. Inbound campaign email from lilliangbriger7886@gmail.com → jcemerald@eod.meh
#   2. Victim reply from jcemerald@eod.meh → lilliangbriger7886@gmail.com
#   3. Attacker follow-up from jcemerald@eod.meh (forwarded back in)
#   4. Internal forwarding to elvine@eod.meh
#   5. Further reply chain
#
# Expected detections:
#   - KnownSender: lilliangbriger7886@gmail.com is a static IOC
#   - CampaignMatch: Lillian Briger body indicators exceed threshold
#   - VictimReply: internal user replies to tracked campaign sender
#   - ConversationEscalation: attacker follows up after victim replied
#   - InternalForwarding: campaign email forwarded to internal colleague
#
# This test uses eod.meh as the internal mail domain.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/conversation.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

# Override internal mail domains to match the anonymized pcap
redef SocialEngineering::internal_mail_domains += {
    "eod.meh",
};

# Tracking counters for each notice type
global known_sender_count = 0;
global campaign_count = 0;
global body_count = 0;
global victim_reply_count = 0;
global escalation_count = 0;
global forwarding_count = 0;
global subject_count = 0;

# Details for verification
global victim_details: vector of string = vector();
global escalation_details: vector of string = vector();
global forwarding_details: vector of string = vector();
global campaign_senders: set[string] = set();
global campaign_subjects: set[string] = set();

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::KnownSender )
        ++known_sender_count;
    else if ( n$note == SocialEngineering::SubjectMatch )
        ++subject_count;
    else if ( n$note == SocialEngineering::BodyIndicators )
        ++body_count;
    else if ( n$note == SocialEngineering::CampaignMatch )
        {
        ++campaign_count;
        add campaign_senders[n$sub];
        }
    else if ( n$note == SocialEngineering::VictimReply )
        {
        ++victim_reply_count;
        victim_details += n$msg;
        }
    else if ( n$note == SocialEngineering::ConversationEscalation )
        {
        ++escalation_count;
        escalation_details += n$msg;
        }
    else if ( n$note == SocialEngineering::InternalForwarding )
        {
        ++forwarding_count;
        forwarding_details += n$msg;
        }
    }

event zeek_done()
    {
    print "=== Conversation Lifecycle Test (conversation.pcap) ===";
    print "";

    # --- Layer 1: Known sender IOC detection ---
    print fmt("KnownSender:             %d", known_sender_count);
    if ( known_sender_count > 0 )
        print "  PASS: Known sender IOC detections fired";
    else
        print "  FAIL: No known sender detections (lilliangbriger7886 should match)";

    # --- Layer 2: Subject pattern matching ---
    print fmt("SubjectMatch:            %d", subject_count);

    # --- Layer 3: Body indicator scoring ---
    print fmt("BodyIndicators:          %d", body_count);

    # --- Layer 4: High-confidence campaign detection ---
    print fmt("CampaignMatch:           %d", campaign_count);
    if ( campaign_count > 0 )
        print "  PASS: Campaign match detections fired";
    else
        print "  FAIL: No campaign match detections";

    # --- Layer 6: Victim reply detection ---
    print fmt("VictimReply:             %d", victim_reply_count);
    if ( victim_reply_count > 0 )
        {
        print "  PASS: VictimReply fired (internal user replied to campaign)";
        for ( i in victim_details )
            print fmt("  Detail: %s", victim_details[i]);
        }
    else
        print "  FAIL: VictimReply did NOT fire (expected reply from eod.meh user)";

    # --- Conversation escalation detection ---
    print fmt("ConversationEscalation:  %d", escalation_count);
    if ( escalation_count > 0 )
        {
        print "  PASS: ConversationEscalation fired (attacker followed up after reply)";
        for ( i in escalation_details )
            print fmt("  Detail: %s", escalation_details[i]);
        }
    else
        print "  INFO: ConversationEscalation did not fire";

    # --- Internal forwarding detection ---
    print fmt("InternalForwarding:      %d", forwarding_count);
    if ( forwarding_count > 0 )
        {
        print "  PASS: InternalForwarding fired (campaign forwarded internally)";
        for ( i in forwarding_details )
            print fmt("  Detail: %s", forwarding_details[i]);
        }
    else
        print "  INFO: InternalForwarding did not fire";

    # --- Conversation state verification ---
    local state_count = |SocialEngineering::conversation_states|;
    print "";
    print fmt("Conversation states:     %d entries", state_count);
    for ( key, state in SocialEngineering::conversation_states )
        print fmt("  [%s] = %s", key, state);

    # --- Internal domain configuration verification ---
    print "";
    if ( "eod.meh" in SocialEngineering::internal_mail_domains )
        print "PASS: Internal domain 'eod.meh' is configured";
    else
        print "FAIL: Internal domain 'eod.meh' not configured";

    # --- Summary ---
    print "";
    local total = known_sender_count + campaign_count + victim_reply_count +
                  escalation_count + forwarding_count;
    print fmt("Total detections:        %d", total);
    print "=== END ===";
    }
