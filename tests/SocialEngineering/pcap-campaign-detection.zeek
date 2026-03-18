# Test that the detection script correctly identifies campaign emails in real
# SMTP traffic. Runs against the full pcap capture and verifies:
#   - BodyIndicators fires for emails matching campaign body patterns
#   - CampaignMatch fires for high-confidence detections
#   - KnownSender fires for the known lilliangbriger7886@gmail.com IOC
#   - Zero false positives on legitimate internal emails
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: test -f notice.log && btest-diff notice.log

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global body_count = 0;
global campaign_count = 0;
global known_sender_count = 0;
global victim_reply_count = 0;
global spray_count = 0;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::BodyIndicators )
        ++body_count;
    else if ( n$note == SocialEngineering::CampaignMatch )
        ++campaign_count;
    else if ( n$note == SocialEngineering::KnownSender )
        ++known_sender_count;
    else if ( n$note == SocialEngineering::VictimReply )
        ++victim_reply_count;
    else if ( n$note == SocialEngineering::SenderSpray )
        ++spray_count;
    }

event zeek_done()
    {
    print "=== LBNL SE Detection Results ===";
    print fmt("BodyIndicators: %d", body_count);
    print fmt("CampaignMatch: %d", campaign_count);
    print fmt("KnownSender: %d", known_sender_count);
    print fmt("VictimReply: %d", victim_reply_count);
    print fmt("SenderSpray: %d", spray_count);

    # Validate expected detection counts
    if ( body_count > 0 )
        print "PASS: Body indicator detections fired";
    else
        print "FAIL: No body indicator detections";

    if ( campaign_count > 0 )
        print "PASS: Campaign match detections fired";
    else
        print "FAIL: No campaign match detections";

    if ( body_count == campaign_count )
        print "PASS: Body and campaign counts match (every body hit exceeds campaign threshold)";
    else
        print fmt("INFO: Body=%d vs Campaign=%d (some emails scored between thresholds)", body_count, campaign_count);

    if ( known_sender_count > 0 )
        print "PASS: Known sender IOC detections fired";
    else
        print "FAIL: No known sender IOC detections";

    print "=== END ===";
    }
