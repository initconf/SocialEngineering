# Test that subject line patterns correctly match campaign subjects
# and correctly reject non-matching subjects.
#
# @TEST-EXEC: ln -sf $PACKAGE SocialEngineering
# @TEST-EXEC: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output

@load base/protocols/smtp
@load base/frameworks/notice

@load SocialEngineering

event zeek_init()
    {
    # --- Subjects that SHOULD match ---
    local should_match: vector of string = {
        "A question on energy efficient buildings and healthy indoor environments",
        "A question on building ventilation and indoor environmental quality",
        "A question on climate modeling and Earth system interactions",
        "A question on computing infrastructure for particle physics",
        "A question on accelerator physics and laser-plasma technology",
        "A question on molecular dynamics in strong laser fields",
        "A question on catalysis and surface chemistry",
        "A question on battery interfaces and electrochemical energy storage",
        "A question on superconducting magnet technology",
        "A question on DNA repair and structural biology",
        "A question on genomic regulators of cardiovascular risk",
        "A question on microbiology and sustainable bioenergy",
        "A question on combustion physics and low-emission systems",
        "A question on spectroscopy and nanoscale imaging",
        "A question on sustainable transportation systems",
        "A question on indoor environmental quality",
        "A question on energy efficiency and management standards",
        "Re: A question on energy efficient buildings",
    };

    for ( i in should_match )
        {
        local matched = F;
        for ( p in SocialEngineering::subject_patterns )
            {
            if ( p in should_match[i] )
                {
                matched = T;
                break;
                }
            }
        if ( matched )
            print fmt("PASS: subject matched: %s", should_match[i]);
        else
            print fmt("FAIL: subject did NOT match: %s", should_match[i]);
        }

    # --- Subjects that should NOT match ---
    local should_not_match: vector of string = {
        "Meeting tomorrow at 3pm",
        "Re: Budget proposal for FY2026",
        "Weekly status update",
        "Paper review request",
        "Invitation to seminar on quantum computing",
        "Question about your availability next week",
    };

    for ( j in should_not_match )
        {
        local matched2 = F;
        for ( p2 in SocialEngineering::subject_patterns )
            {
            if ( p2 in should_not_match[j] )
                {
                matched2 = T;
                break;
                }
            }
        if ( ! matched2 )
            print fmt("PASS: correctly rejected: %s", should_not_match[j]);
        else
            print fmt("FAIL: false positive on: %s", should_not_match[j]);
        }
    }
