# Test that the reply detection configuration is properly loaded.
# Validates internal domains, tracking tables, and configuration defaults.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

event zeek_init()
    {
    # --- Test 1: Internal mail domains are configured ---
    if ( "eod.meh" in SocialEngineering::internal_mail_domains )
        print "PASS: eod.meh is in internal_mail_domains";
    else
        print "FAIL: eod.meh missing from internal_mail_domains";

    # External domains should NOT be in the set
    if ( "gmail.com" !in SocialEngineering::internal_mail_domains )
        print "PASS: gmail.com is not in internal_mail_domains";
    else
        print "FAIL: gmail.com incorrectly in internal_mail_domains";

    # --- Test 2: Alert email destination is configured ---
    if ( SocialEngineering::alert_email_dest == "ir-dev@eod.meh" )
        print fmt("PASS: alert_email_dest = %s", SocialEngineering::alert_email_dest);
    else
        print fmt("FAIL: alert_email_dest = %s (expected ir-dev@eod.meh)", SocialEngineering::alert_email_dest);

    # --- Test 3: Tracking tables start empty ---
    if ( |SocialEngineering::tracked_campaign_senders| == 0 )
        print "PASS: tracked_campaign_senders starts empty";
    else
        print "FAIL: tracked_campaign_senders is not empty at init";

    if ( |SocialEngineering::tracked_campaign_msg_ids| == 0 )
        print "PASS: tracked_campaign_msg_ids starts empty";
    else
        print "FAIL: tracked_campaign_msg_ids is not empty at init";

    if ( |SocialEngineering::tracked_campaign_subjects| == 0 )
        print "PASS: tracked_campaign_subjects starts empty";
    else
        print "FAIL: tracked_campaign_subjects is not empty at init";

    # --- Test 4: VictimReply notice type exists ---
    local vr = SocialEngineering::VictimReply;
    print fmt("PASS: VictimReply notice type = %s", vr);
    }
