# Test MIME structure fingerprinting.
#
# Verifies:
#   - MimeFingerprint correctly detects multipart, HTML, entity counts
#   - PLAIN_TEXT_STRUCTURE amplifier does NOT fire on multipart/HTML emails
#     (campaign samples are multipart with HTML — correctly suppressed)
#   - Amplifier gate prevents firing on zero-score emails
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global multipart_count = 0;
global html_count = 0;
global total_fingerprinted = 0;
global plain_text_amplifier_count = 0;

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=-3
    {
    if ( code == 250 && (cmd == "." || cmd == "BDAT") && c?$smtp )
        {
        if ( c$uid in SocialEngineering::conn_mime_fp )
            {
            ++total_fingerprinted;
            local fp = SocialEngineering::conn_mime_fp[c$uid];
            if ( fp$has_multipart )
                ++multipart_count;
            if ( fp$has_html )
                ++html_count;
            }
        }
    }

hook Notice::policy(n: Notice::Info)
    {
    if ( /PLAIN_TEXT_STRUCTURE/ in n$msg )
        ++plain_text_amplifier_count;
    }

event zeek_done()
    {
    print fmt("Emails fingerprinted: %d", total_fingerprinted);
    print fmt("Multipart detected: %d", multipart_count);
    print fmt("HTML detected: %d", html_count);

    if ( total_fingerprinted > 0 )
        print "PASS: MIME fingerprinting is active";
    else
        print "FAIL: No emails were fingerprinted";

    if ( multipart_count == total_fingerprinted )
        print "PASS: All campaign emails correctly identified as multipart";
    else
        print fmt("INFO: %d of %d are multipart", multipart_count, total_fingerprinted);

    if ( html_count == total_fingerprinted )
        print "PASS: All campaign emails correctly identified as HTML";
    else
        print fmt("INFO: %d of %d have HTML", html_count, total_fingerprinted);

    # PLAIN_TEXT_STRUCTURE should NOT fire on multipart/HTML emails
    if ( plain_text_amplifier_count == 0 )
        print "PASS: PLAIN_TEXT_STRUCTURE correctly suppressed on multipart/HTML emails";
    else
        print fmt("FAIL: PLAIN_TEXT_STRUCTURE fired %d times on multipart emails", plain_text_amplifier_count);
    }
