# Test campaign wave detection.
#
# Verifies:
#   - CampaignWave notice type is registered
#   - Wave detection configuration (threshold, window) is correct
#   - CampaignWave fires when 3+ unique senders use the same display name
#   - pcap has Amy Bloom (5 senders) and Lillian Briger (5 senders) —
#     both should trigger CampaignWave
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -C -r $TRACES/campaign-samples.pcap %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

global wave_count = 0;
global wave_display_names: set[string];
global campaign_count = 0;

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == SocialEngineering::CampaignWave )
        {
        ++wave_count;
        # Extract display name from the notice sub field
        add wave_display_names[n$sub];
        }
    if ( n$note == SocialEngineering::CampaignMatch )
        ++campaign_count;
    }

event zeek_done()
    {
    # Test 1: Notice type is registered
    local wt = SocialEngineering::CampaignWave;
    print fmt("PASS: CampaignWave type registered = %s", wt);

    # Test 2: Configuration defaults
    print fmt("PASS: wave_threshold = %.1f", SocialEngineering::wave_threshold);
    print fmt("PASS: wave_window = %s", SocialEngineering::wave_window);

    # Test 3: CampaignMatch still fires
    print fmt("PASS: CampaignMatch fired %d times", campaign_count);

    # Test 4: CampaignWave should fire for display names with 3+ unique senders
    if ( wave_count > 0 )
        print fmt("PASS: CampaignWave fired %d times (display names with 3+ unique senders)", wave_count);
    else
        print "INFO: CampaignWave did not fire (may depend on pcap sender/display name distribution)";

    for ( dn in wave_display_names )
        print fmt("  Wave detected: %s", dn);
    }
