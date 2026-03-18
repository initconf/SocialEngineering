# Test that an internal user replying to a detected campaign email
# triggers a VictimReply notice. Uses campaign-samples-with-reply.pcap
# which contains 10 inbound campaign emails followed by a synthetic
# reply from user12xxx@eod.meh to lilliangbriger7886@gmail.com.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples-with-reply.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global victim_reply_count = 0;
global victim_details: vector of string = vector();
global campaign_count = 0;
global known_sender_count = 0;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::VictimReply )
        {
        ++victim_reply_count;
        victim_details += fmt("Victim: %s", n$msg);
        }
    else if ( n$note == SocialEngineering::CampaignMatch )
        ++campaign_count;
    else if ( n$note == SocialEngineering::KnownSender )
        ++known_sender_count;
    }

event zeek_done()
    {
    print "=== Victim Reply Detection Test ===";

    # Campaign emails should still be detected
    if ( campaign_count > 0 )
        print fmt("PASS: %d campaign emails detected (prerequisite for reply tracking)", campaign_count);
    else
        print "FAIL: No campaign emails detected (reply tracking has no data)";

    # Known sender IOC should fire for lilliangbriger7886@gmail.com
    if ( known_sender_count > 0 )
        print fmt("PASS: %d known sender IOC detections", known_sender_count);
    else
        print "FAIL: No known sender IOC detections";

    # The critical test: VictimReply should fire
    if ( victim_reply_count == 1 )
        {
        print "PASS: VictimReply notice fired (1 reply detected)";
        for ( i in victim_details )
            print fmt("  %s", victim_details[i]);
        }
    else if ( victim_reply_count > 1 )
        print fmt("WARN: VictimReply fired %d times (expected 1)", victim_reply_count);
    else
        print "FAIL: VictimReply notice did NOT fire";

    # Verify the reply was from an internal user to a campaign sender
    if ( victim_reply_count > 0 )
        {
        local detail = victim_details[0];
        if ( /user12xxx@lbl\.gov/ in detail )
            print "PASS: Victim identified as user12xxx@eod.meh";
        else
            print "FAIL: Victim identity not found in notice";

        if ( /lilliangbriger7886@gmail\.com/ in detail )
            print "PASS: Reply recipient is lilliangbriger7886@gmail.com";
        else
            print "FAIL: Campaign sender not found in notice";
        }

    print "=== END ===";
    }
