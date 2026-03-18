# Test no-link/no-attachment amplifier signal.
#
# Verifies:
#   - Campaign emails without URLs/attachments get NO_LINKS_OR_ATTACHMENTS
#   - The signal only fires as an amplifier (score > 0 from other indicators)
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global no_link_count = 0;
global body_count = 0;

hook Notice::policy(n: Notice::Info)
    {
    # BodyIndicators $msg contains the full matched_str with indicator names
    if ( n$note == SocialEngineering::BodyIndicators )
        {
        ++body_count;
        if ( /NO_LINKS_OR_ATTACHMENTS/ in n$msg )
            ++no_link_count;
        }
    }

event zeek_done()
    {
    print fmt("BodyIndicators notices: %d", body_count);
    print fmt("With NO_LINKS_OR_ATTACHMENTS: %d", no_link_count);

    if ( no_link_count > 0 )
        print "PASS: NO_LINKS_OR_ATTACHMENTS amplifier fired on campaign emails";
    else
        print "FAIL: NO_LINKS_OR_ATTACHMENTS amplifier never fired";

    if ( no_link_count == body_count )
        print "PASS: All campaign emails have no links/attachments (expected for this campaign)";
    else
        print fmt("INFO: %d of %d campaign emails had no links", no_link_count, body_count);
    }
