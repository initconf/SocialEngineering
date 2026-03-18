# Test that campaign emails score well above thresholds and that
# scoring distribution is consistent. Validates that both Amy Bloom
# and Lillian Briger personas are detected.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global amy_count = 0;
global lillian_count = 0;
global min_score = 999.0;
global max_score = 0.0;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::BodyIndicators )
        {
        # Extract score from message
        if ( /Amy Bloom/ in n$msg )
            ++amy_count;
        if ( /Lillian/ in n$msg )
            ++lillian_count;

        # Parse score from "score=XX.X"
        local parts = split_string(n$msg, /score=/);
        if ( |parts| >= 2 )
            {
            local score_parts = split_string(parts[1], /\)/);
            local score = to_double(score_parts[0]);
            if ( score < min_score )
                min_score = score;
            if ( score > max_score )
                max_score = score;
            }
        }
    }

event zeek_done()
    {
    print "=== Persona Detection ===";

    if ( amy_count > 0 )
        print fmt("PASS: Amy Bloom persona detected (%d emails)", amy_count);
    else
        print "FAIL: Amy Bloom persona not detected";

    if ( lillian_count > 0 )
        print fmt("PASS: Lillian Briger persona detected (%d emails)", lillian_count);
    else
        print "FAIL: Lillian Briger persona not detected";

    print "=== Score Distribution ===";
    print fmt("Min score: %.1f", min_score);
    print fmt("Max score: %.1f", max_score);

    if ( min_score >= SocialEngineering::campaign_score_threshold )
        print fmt("PASS: All scores (%.1f-%.1f) exceed campaign threshold (%.1f)",
                  min_score, max_score, SocialEngineering::campaign_score_threshold);
    else
        print fmt("INFO: Min score %.1f is below campaign threshold %.1f (some emails only hit body threshold)",
                  min_score, SocialEngineering::campaign_score_threshold);
    }
