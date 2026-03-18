# Test that all expected Notice types are registered and the module loads cleanly.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

event zeek_init()
    {
    # Verify all notice types exist by using them in expressions
    local n1 = SocialEngineering::KnownSender;
    local n2 = SocialEngineering::SubjectMatch;
    local n3 = SocialEngineering::BodyIndicators;
    local n4 = SocialEngineering::CampaignMatch;
    local n5 = SocialEngineering::SenderSpray;
    local n6 = SocialEngineering::VictimReply;
    local n7 = SocialEngineering::DisplayNameReuse;
    local n8 = SocialEngineering::InternalForwarding;
    local n9 = SocialEngineering::ConversationEscalation;
    local n10 = SocialEngineering::CampaignWave;

    print fmt("PASS: KnownSender = %s", n1);
    print fmt("PASS: SubjectMatch = %s", n2);
    print fmt("PASS: BodyIndicators = %s", n3);
    print fmt("PASS: CampaignMatch = %s", n4);
    print fmt("PASS: SenderSpray = %s", n5);
    print fmt("PASS: VictimReply = %s", n6);
    print fmt("PASS: DisplayNameReuse = %s", n7);
    print fmt("PASS: InternalForwarding = %s", n8);
    print fmt("PASS: ConversationEscalation = %s", n9);
    print fmt("PASS: CampaignWave = %s", n10);

    # Verify configuration defaults
    print fmt("PASS: spray_threshold = %.1f", SocialEngineering::spray_threshold);
    print fmt("PASS: spray_window = %s", SocialEngineering::spray_window);
    print fmt("PASS: alert_email_dest = %s", SocialEngineering::alert_email_dest);
    print fmt("PASS: campaign_tracking_expiry = %s", SocialEngineering::campaign_tracking_expiry);
    }
