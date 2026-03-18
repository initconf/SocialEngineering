# Test that legitimate internal emails in the pcap do NOT trigger any
# campaign detections. Verifies false positive rate by checking that
# only known campaign senders/patterns trigger alerts.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

# Track all notice subjects to check for false positives on anonymized internal senders
global legitimate_senders: set[string] = {
    "user1xxx@eod.meh",
    "user2xx@eod.meh",
    "user3x@eod.meh",
    "user4xxx@eod.meh",
    "user5x@eod.meh",
};

global false_positives: vector of string = vector();

hook Notice::policy(n: Notice::Info)
    {
    # Check if any notice fires for a known legitimate sender
    if ( n?$sub )
        {
        for ( legit in legitimate_senders )
            {
            if ( legit in n$sub )
                false_positives += fmt("FALSE POSITIVE: %s triggered %s (sub=%s)", legit, n$note, n$sub);
            }
        }
    }

event zeek_done()
    {
    if ( |false_positives| == 0 )
        print "PASS: Zero false positives on legitimate internal senders";
    else
        {
        print fmt("FAIL: %d false positives detected:", |false_positives|);
        for ( i in false_positives )
            print false_positives[i];
        }
    }
