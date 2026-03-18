# Test that known IOC sender addresses and display names are properly loaded.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

event zeek_init()
    {
    # --- Test 1: Known bad sender address should be in the IOC set ---
    if ( "lilliangbriger7886@gmail.com" in SocialEngineering::known_bad_senders )
        print "PASS: lilliangbriger7886@gmail.com is in known_bad_senders";
    else
        print "FAIL: lilliangbriger7886@gmail.com missing from known_bad_senders";

    # --- Test 2: Known display names are loaded ---
    if ( "Amy Bloom" in SocialEngineering::known_bad_display_names )
        print "PASS: Amy Bloom is in known_bad_display_names";
    else
        print "FAIL: Amy Bloom missing from known_bad_display_names";

    if ( "Lillian Briger" in SocialEngineering::known_bad_display_names )
        print "PASS: Lillian Briger is in known_bad_display_names";
    else
        print "FAIL: Lillian Briger missing from known_bad_display_names";

    if ( "Lillian GBriger" in SocialEngineering::known_bad_display_names )
        print "PASS: Lillian GBriger is in known_bad_display_names";
    else
        print "FAIL: Lillian GBriger missing from known_bad_display_names";
    }
