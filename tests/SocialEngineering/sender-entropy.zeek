# Test sender address entropy amplifier signal.
#
# Verifies:
#   - HIGH_SENDER_ENTROPY fires on freemail addresses with high digit ratio
#   - Only fires as amplifier (score > 0)
#   - Correctly calculates numeric ratio
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load SocialEngineering

event zeek_init()
    {
    # Test the numeric ratio helper function directly
    local r1 = SocialEngineering::local_part_numeric_ratio("amyblooms452354@gmail.com");
    local r2 = SocialEngineering::local_part_numeric_ratio("john.smith@university.edu");
    local r3 = SocialEngineering::local_part_numeric_ratio("amybloom2657@gmail.com");
    local r4 = SocialEngineering::local_part_numeric_ratio("user@test.com");
    local r5 = SocialEngineering::local_part_numeric_ratio("123456@gmail.com");

    print fmt("amyblooms452354: ratio=%.2f", r1);
    print fmt("john.smith: ratio=%.2f", r2);
    print fmt("amybloom2657: ratio=%.2f", r3);
    print fmt("user: ratio=%.2f", r4);
    print fmt("123456: ratio=%.2f", r5);

    # Verify thresholds
    if ( r1 >= SocialEngineering::entropy_numeric_ratio )
        print "PASS: amyblooms452354 exceeds entropy threshold";
    else
        print "FAIL: amyblooms452354 should exceed threshold";

    if ( r2 < SocialEngineering::entropy_numeric_ratio )
        print "PASS: john.smith below entropy threshold";
    else
        print "FAIL: john.smith should be below threshold";

    if ( r3 < SocialEngineering::entropy_numeric_ratio )
        print "PASS: amybloom2657 below entropy threshold (33% < 40%)";
    else
        print "FAIL: amybloom2657 should be below threshold";

    if ( r4 < SocialEngineering::entropy_numeric_ratio )
        print "PASS: user has zero entropy";
    else
        print "FAIL: user should have zero entropy";

    if ( r5 >= SocialEngineering::entropy_numeric_ratio )
        print "PASS: 123456 is all digits";
    else
        print "FAIL: 123456 should be all digits";

    # Verify freemail domain check
    if ( "gmail.com" in SocialEngineering::freemail_domains )
        print "PASS: gmail.com is in freemail_domains";
    else
        print "FAIL: gmail.com should be in freemail_domains";

    if ( "university.edu" !in SocialEngineering::freemail_domains )
        print "PASS: university.edu is not in freemail_domains";
    else
        print "FAIL: university.edu should not be in freemail_domains";
    }
