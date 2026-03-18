# Test that internal senders are never added to learned IOC sets,
# tracked campaign senders, contact pairs, or conversation state tables.
#
# The conversation.pcap contains an internal user (jcemerald@eod.meh)
# who replies to a campaign email from lilliangbriger7886@gmail.com.
# The reply scores above campaign_score_threshold (via subject pattern
# + body content). Without the internal-sender guard, this would add
# jcemerald@eod.meh to learned_bad_senders — causing every subsequent
# email FROM jcemerald to be flagged as a campaign email (false positive).
#
# Verifies:
#   - External campaign sender IS learned (lilliangbriger7886@gmail.com)
#   - Internal sender is NOT in learned_bad_senders
#   - Internal sender is NOT in tracked_campaign_senders
#   - Internal sender is NOT in campaign_contact_pairs (as attacker)
#   - Reply subject from internal sender is NOT in learned_bad_subjects
#   - External campaign subjects ARE in learned_bad_subjects
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

# Helper: check if an email address belongs to an internal domain.
# (is_internal_sender is not exported, so we replicate the logic here.)
function is_internal(email: string): bool
    {
    local parts = split_string(email, /@/);
    if ( |parts| == 2 )
        return to_lower(parts[1]) in SocialEngineering::internal_mail_domains;
    return F;
    }

event zeek_done()
    {
    print "=== Internal Sender Learning Guard Test ===";
    print "";

    # --- Learned senders ---
    print fmt("Learned bad senders: %d entries", |SocialEngineering::learned_bad_senders|);
    for ( s in SocialEngineering::learned_bad_senders )
        print fmt("  learned_sender: %s", s);

    # External campaign sender SHOULD be learned
    if ( "lilliangbriger7886@gmail.com" in SocialEngineering::learned_bad_senders )
        print "PASS: External campaign sender learned (lilliangbriger7886@gmail.com)";
    else
        print "FAIL: External campaign sender NOT learned";

    # Internal senders MUST NOT be learned
    local internal_learned = F;
    for ( ls in SocialEngineering::learned_bad_senders )
        {
        if ( is_internal(ls) )
            {
            internal_learned = T;
            print fmt("FAIL: Internal sender learned as IOC: %s", ls);
            }
        }
    if ( ! internal_learned )
        print "PASS: No internal senders in learned_bad_senders";

    # --- Tracked campaign senders ---
    print "";
    print fmt("Tracked campaign senders: %d entries", |SocialEngineering::tracked_campaign_senders|);
    for ( ts in SocialEngineering::tracked_campaign_senders )
        print fmt("  tracked_sender: %s", ts);

    local internal_tracked = F;
    for ( ts2 in SocialEngineering::tracked_campaign_senders )
        {
        if ( is_internal(ts2) )
            {
            internal_tracked = T;
            print fmt("FAIL: Internal sender tracked as campaign sender: %s", ts2);
            }
        }
    if ( ! internal_tracked )
        print "PASS: No internal senders in tracked_campaign_senders";

    # --- Learned subjects ---
    print "";
    print fmt("Learned bad subjects: %d entries", |SocialEngineering::learned_bad_subjects|);
    for ( subj in SocialEngineering::learned_bad_subjects )
        print fmt("  learned_subject: %s", subj);

    # --- Contact pairs: internal sender must not appear as attacker key ---
    print "";
    local internal_attacker = F;
    for ( cp_sender, cp_rcpts in SocialEngineering::campaign_contact_pairs )
        {
        if ( is_internal(cp_sender) )
            {
            internal_attacker = T;
            print fmt("FAIL: Internal sender in contact pairs as attacker: %s", cp_sender);
            }
        }
    if ( ! internal_attacker )
        print "PASS: No internal senders as attacker in campaign_contact_pairs";

    # --- Conversation states: internal sender must not appear as attacker ---
    local internal_conv_attacker = F;
    for ( cs_key, cs_state in SocialEngineering::conversation_states )
        {
        local parts = split_string(cs_key, /,/);
        if ( |parts| >= 1 && is_internal(parts[0]) )
            {
            internal_conv_attacker = T;
            print fmt("FAIL: Internal sender as attacker in conversation_states: %s", cs_key);
            }
        }
    if ( ! internal_conv_attacker )
        print "PASS: No internal senders as attacker in conversation_states";

    print "";
    print "=== END ===";
    }
