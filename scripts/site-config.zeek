##! Site-specific configuration for the SocialEngineering package.
##!
##! This file populates the campaign IOCs, subject patterns, internal domains,
##! and alerting destinations.  Override any value from local.zeek using redef.

module SocialEngineering;

# ---------------------------------------------------------------------------
# KNOWN SENDER IOCs
# ---------------------------------------------------------------------------

redef known_bad_senders += {
    "lilliangbriger7886@gmail.com",
};

redef known_bad_sender_patterns += {
    /amyblooms?[0-9]+@gmail\.com/,
    /lilliang?briger\.?[a-z]*[0-9]*@gmail\.com/,
};

redef known_bad_display_names += {
    "Amy Bloom",
    "Lillian Briger",
    "Lillian GBriger",
};

# ---------------------------------------------------------------------------
# SUBJECT LINE PATTERNS
# ---------------------------------------------------------------------------

redef subject_patterns += {
    ## --- Core science & computing ---
    /[Aa] question (about|on) .*(energy|building|climate|computing|accelerat|particl|molecul|catalys|battery|superconduct|DNA|genom|microbi|combustion|spectroscop|transport)/,
    /[Aa] question (about|on) .*(indoor environment|sustainable|efficiency)/,

    ## --- Physics & instrumentation ---
    /[Aa] question (about|on) .*(neutrino|nuclear|quantum|synchrotron|x.ray|cryo.EM|laser|plasma|photon|SQUID|scintillat|crystallograph)/,
    /[Aa] question (about|on) .*(free.electron|light source|ultrafast|optics|coherent)/,

    ## --- Biology & life sciences ---
    /[Aa] question (about|on) .*(structural biology|synthetic biology|bioinformatics|proteomics|metabol|protein dynamics|lipid|biomolec|gene delivery|microbiome)/,
    /[Aa] question (about|on) .*(qPCR|biosynthesis|mycorrhizal|lignin|demethylase|glycosyltransferase|catabolite|metagenom)/,
    /[Aa] question (about|on) .*(brain imaging|neurodegen|cancer biology|cell microenviron|aging)/,

    ## --- Earth, environment & subsurface ---
    /[Aa] question (about|on) .*(biogeochem|subsurface|geophysi|geochemis|isotope|earthquake|watershed|snowpack|hydroclimate)/,
    /[Aa] question (about|on) .*(ecosystem|carbon (observation|storage|feedbacks)|environmental (chemistry|genomics|modeling))/,
    /[Aa] question (about|on) .*(extreme (weather|climate)|climate (statistics|risk|prediction|observations))/,

    ## --- Materials, chemistry & nanoscience ---
    /[Aa] question (about|on) .*(nanomaterial|nanoscale|nanomanufactur|materials (science|fabricat)|surface chemistry|polymer|metal ion|solar fuel)/,
    /[Aa] question (about|on) .*(electrochemical|lithium|mineral|advanced materials)/,

    ## --- Computing & data infrastructure ---
    /[Aa] question (about|on) .*(high.performance computing|exascale|supercomput|scientific (computing|simulation|data|networking|visualization|instrumentation))/,
    /[Aa] question (about|on) .*(machine learning|numerical|scalable algorithms|AI.driven|mathematics|experimental discovery)/,
    /[Aa] question (about|on) .*(data (driven|intensive|movement|systems|platforms)|large.scale.*computing)/,

    ## --- Energy systems & grid ---
    /[Aa] question (about|on) .*(grid (modernization|integration)|electricity market|renewable energy|distributed (solar|energy)|electric vehicle)/,
    /[Aa] question (about|on) .*(thermal energy|HVAC|window technolog|decarbonization|building energy|energy management)/,
    /[Aa] question (about|on) .*(dark energy|cosmology)/,

    ## --- Facilities & engineering ---
    /[Aa] question (about|on) .*(large scientific (facilit|laborator)|research (infrastructure|collaboration)|control systems|engineering (design|at))/,
    /[Aa] question (about|on) .*(Molecular Foundry|operations|safety|governance|risk management)/,
    /[Aa] question (about|on) .*(managing.*facilit|supporting.*infrastructure)/,

    ## --- Catch-all for common campaign framing ---
    /[Aa] question (about|on) .*the future/,
    /[Aa] question (about|on) .*next.generation/,
    /[Aa] question (about|on) .*how .*(understand|shapes|supports)/,

    ## --- Reply subjects ---
    /[Rr]e: [Aa] question (about|on)/,
    /[Ff]wd: [Aa] question (about|on)/,
};

# ---------------------------------------------------------------------------
# INTERNAL MAIL DOMAINS & ALERTING
# ---------------------------------------------------------------------------

redef internal_mail_domains += {
    "eod.meh",
};

redef alert_email_dest = "ir-dev@eod.meh";

# ---------------------------------------------------------------------------
# HIGH-VALUE TARGETS
# ---------------------------------------------------------------------------
# Add email addresses of VIPs who warrant escalated alerting.
# Example:
#   redef SocialEngineering::high_value_targets += {
#       "director@eod.meh",
#       "division-head@eod.meh",
#   };
