# Test that body content indicators are properly defined and weighted.
# Validates the scoring logic by checking indicator weights and patterns.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

event zeek_init()
    {
    # --- Test 1: Verify body indicators are loaded ---
    local count_indicators = |SocialEngineering::body_indicators|;
    if ( count_indicators >= 20 )
        print fmt("PASS: %d body indicators loaded (expected >= 20)", count_indicators);
    else
        print fmt("FAIL: only %d body indicators loaded (expected >= 20)", count_indicators);

    # --- Test 2: Verify score thresholds ---
    if ( SocialEngineering::body_score_threshold == 6.0 )
        print fmt("PASS: body_score_threshold = %.1f", SocialEngineering::body_score_threshold);
    else
        print fmt("FAIL: body_score_threshold = %.1f (expected 6.0)", SocialEngineering::body_score_threshold);

    if ( SocialEngineering::campaign_score_threshold == 8.0 )
        print fmt("PASS: campaign_score_threshold = %.1f", SocialEngineering::campaign_score_threshold);
    else
        print fmt("FAIL: campaign_score_threshold = %.1f (expected 8.0)", SocialEngineering::campaign_score_threshold);

    # --- Test 3: Verify key patterns match expected content ---
    local amy_bio = "I grew up in Monaco and later studied design in Paris";
    local amy_matched = F;
    for ( i in SocialEngineering::body_indicators )
        {
        if ( SocialEngineering::body_indicators[i]$description == "Amy Bloom bio fingerprint" )
            {
            if ( SocialEngineering::body_indicators[i]$pattern_match in amy_bio )
                {
                amy_matched = T;
                print fmt("PASS: Amy Bloom bio pattern matches (weight=%.1f)",
                          SocialEngineering::body_indicators[i]$weight);
                }
            }
        }
    if ( ! amy_matched )
        print "FAIL: Amy Bloom bio pattern did not match expected text";

    local lillian_bio = "I grew up in Brunei and later studied business administration at Stanford";
    local lillian_matched = F;
    for ( j in SocialEngineering::body_indicators )
        {
        if ( SocialEngineering::body_indicators[j]$description == "Lillian Briger bio fingerprint" )
            {
            if ( SocialEngineering::body_indicators[j]$pattern_match in lillian_bio )
                {
                lillian_matched = T;
                print fmt("PASS: Lillian Briger bio pattern matches (weight=%.1f)",
                          SocialEngineering::body_indicators[j]$weight);
                }
            }
        }
    if ( ! lillian_matched )
        print "FAIL: Lillian Briger bio pattern did not match expected text";

    # --- Test 4: Verify manipulation indicators have high weights ---
    for ( k in SocialEngineering::body_indicators )
        {
        local ind = SocialEngineering::body_indicators[k];
        if ( ind$description == "Guilt manipulation phrase" )
            {
            if ( ind$weight >= 5.0 )
                print fmt("PASS: Guilt manipulation weight = %.1f (high priority)", ind$weight);
            else
                print fmt("FAIL: Guilt manipulation weight = %.1f (expected >= 5.0)", ind$weight);
            }
        if ( ind$description == "Emotional pressure phrase" )
            {
            if ( ind$weight >= 5.0 )
                print fmt("PASS: Emotional pressure weight = %.1f (high priority)", ind$weight);
            else
                print fmt("FAIL: Emotional pressure weight = %.1f (expected >= 5.0)", ind$weight);
            }
        }

    # --- Test 5: Verify closing phrase pattern ---
    local closing = "If you ever have a moment to share a quick thought";
    local closing_matched = F;
    for ( m in SocialEngineering::body_indicators )
        {
        if ( SocialEngineering::body_indicators[m]$description == "Campaign closing phrase" )
            {
            if ( SocialEngineering::body_indicators[m]$pattern_match in closing )
                {
                closing_matched = T;
                print "PASS: Campaign closing phrase pattern matches";
                }
            }
        }
    if ( ! closing_matched )
        print "FAIL: Campaign closing phrase pattern did not match expected text";
    }
