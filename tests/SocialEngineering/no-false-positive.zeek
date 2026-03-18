# Test that benign content does NOT trigger campaign detection.
# Ensures legitimate academic correspondence is not flagged.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

event zeek_init()
    {
    # --- Test 1: Legitimate sender should not be in IOC lists ---
    if ( "professor@example.edu" !in SocialEngineering::known_bad_senders )
        print "PASS: legitimate sender not in known_bad_senders";
    else
        print "FAIL: legitimate sender incorrectly in known_bad_senders";

    # --- Test 2: Legitimate academic phrases should score below threshold ---
    # Simulate scoring of a normal academic email body
    local benign_body = "Dear Dr. Smith, I recently read your paper on climate modeling. I found it fascinating how your approach differs from traditional methods. Would you be available for a meeting next week? Best regards, Jane";

    local score = 0.0;
    for ( i in SocialEngineering::body_indicators )
        {
        if ( SocialEngineering::body_indicators[i]$pattern_match in benign_body )
            score += SocialEngineering::body_indicators[i]$weight;
        }

    if ( score < SocialEngineering::body_score_threshold )
        print fmt("PASS: benign email scored %.1f (below threshold %.1f)",
                  score, SocialEngineering::body_score_threshold);
    else
        print fmt("FAIL: benign email scored %.1f (at or above threshold %.1f)",
                  score, SocialEngineering::body_score_threshold);

    # --- Test 3: Campaign email body SHOULD score above threshold ---
    local malicious_body = "My name is Amy Bloom. I grew up in Monaco and later studied design in Paris before completing finance studies in the United States. Today my work sits at the intersection of private art collections, long-term investment structures, and scientific philanthropy. Over the past decade I have had the privilege of collaborating with several royal families as well as established European and American family offices on initiatives supporting research, education, and cultural projects. It is fascinating how advances in computing infrastructure increasingly shape breakthroughs. If you ever have a moment to share a quick thought, I would genuinely enjoy hearing your perspective.";

    local mal_score = 0.0;
    local mal_matched: vector of string = vector();
    for ( j in SocialEngineering::body_indicators )
        {
        if ( SocialEngineering::body_indicators[j]$pattern_match in malicious_body )
            {
            mal_score += SocialEngineering::body_indicators[j]$weight;
            mal_matched += SocialEngineering::body_indicators[j]$description;
            }
        }

    if ( mal_score >= SocialEngineering::campaign_score_threshold )
        print fmt("PASS: campaign email scored %.1f (above campaign threshold %.1f)",
                  mal_score, SocialEngineering::campaign_score_threshold);
    else
        print fmt("FAIL: campaign email scored %.1f (below campaign threshold %.1f)",
                  mal_score, SocialEngineering::campaign_score_threshold);

    print fmt("INFO: campaign email matched %d indicators", |mal_matched|);
    for ( k in mal_matched )
        print fmt("  - %s", mal_matched[k]);
    }
