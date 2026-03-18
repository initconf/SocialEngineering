# Test that the known IOC sender lilliangbriger7886@gmail.com is detected
# in the pcap traffic and fires KnownSender notices.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global ioc_hits: vector of string = vector();

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::KnownSender )
        ioc_hits += n$msg;
    }

event zeek_done()
    {
    print fmt("KnownSender notices: %d", |ioc_hits|);

    if ( |ioc_hits| > 0 )
        {
        print "PASS: Known sender IOC detected in pcap";
        for ( i in ioc_hits )
            print fmt("  HIT: %s", ioc_hits[i]);
        }
    else
        print "FAIL: Known sender IOC not detected in pcap";
    }
