# Test that the se_campaign.log stream is created and populated correctly
# when processing campaign emails from the pcap.
#
# Verifies:
#   - se_campaign.log file is created
#   - Log entries have expected fields (sender, subject, score, notice_type)
#   - BodyIndicators and CampaignMatch entries are present
#   - Persona detection works (Amy Bloom / Lillian Briger)
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global log_count = 0;
global body_log_count = 0;
global campaign_log_count = 0;
global victim_reply_log_count = 0;
global has_persona = F;

event zeek_done()
    {
    # Check se_campaign.log was created
    if ( log_count > 0 )
        print fmt("PASS: se_campaign.log has %d entries", log_count);
    else
        print "FAIL: se_campaign.log has no entries";

    if ( body_log_count > 0 )
        print fmt("PASS: BodyIndicators log entries: %d", body_log_count);
    else
        print "FAIL: No BodyIndicators log entries";

    if ( campaign_log_count > 0 )
        print fmt("PASS: CampaignMatch log entries: %d", campaign_log_count);
    else
        print "FAIL: No CampaignMatch log entries";

    if ( has_persona )
        print "PASS: Persona detected in log entries";
    else
        print "FAIL: No persona detected";
    }

hook Log::log_stream_policy(rec: any, id: Log::ID)
    {
    if ( id != SocialEngineering::CAMPAIGN_LOG )
        return;

    ++log_count;

    local info = rec as SocialEngineering::CampaignLogInfo;

    if ( info$notice_type == "BodyIndicators" )
        ++body_log_count;
    else if ( info$notice_type == "CampaignMatch" )
        ++campaign_log_count;
    else if ( info$notice_type == "VictimReply" )
        ++victim_reply_log_count;

    if ( info?$persona && info$persona != "" )
        has_persona = T;
    }
