# logging.zeek — Dedicated se_campaign.log stream.
#
# Provides structured logging of all campaign detection events for SIEM
# ingestion and threat hunting. Each notice event writes a corresponding
# row to se_campaign.log with rich metadata.

module SocialEngineering;

# Detect persona from matched indicators string
function detect_persona(matched: string): string
    {
    if ( /Amy Bloom/ in matched )
        return "Amy Bloom";
    if ( /Lillian Briger/ in matched )
        return "Lillian Briger";
    return "";
    }

# Write a campaign log entry. Called from detection.zeek at each notice point.
function write_campaign_log(c: connection, sender: string, subject: string,
                            score: double, matched: string,
                            notice_type: string, is_learned: bool)
    {
    local info = CampaignLogInfo(
        $ts           = network_time(),
        $uid          = c$uid,
        $id           = c$id,
        $sender       = sender,
        $subject      = subject,
        $score        = score,
        $matched_indicators = matched,
        $notice_type  = notice_type,
        $is_learned   = is_learned
    );

    local persona = detect_persona(matched);
    if ( persona != "" )
        info$persona = persona;

    if ( c?$smtp && c$smtp?$rcptto )
        info$recipients = cat(c$smtp$rcptto);

    Log::write(CAMPAIGN_LOG, info);
    }

event zeek_init() &priority=10
    {
    Log::create_stream(CAMPAIGN_LOG,
        [$columns=CampaignLogInfo, $path="se_campaign"]);
    }
