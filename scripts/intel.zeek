# intel.zeek — Intel framework integration.
#
# Feeds confirmed CampaignMatch senders into Zeek's Intel framework so
# other scripts and downstream SIEM see the IOC automatically.
# Intel::insert() is cluster-safe — the framework handles distribution.

module SocialEngineering;

# Insert an indicator into the Intel framework.
# Called from detection.zeek when a CampaignMatch fires.
function insert_intel_indicator(indicator: string, indicator_type: Intel::Type,
                                 desc: string)
    {
    Intel::insert(Intel::Item(
        $indicator      = indicator,
        $indicator_type = indicator_type,
        $meta           = Intel::MetaData(
            $source = "SocialEngineering",
            $desc   = desc
        )
    ));
    }
