# cluster.zeek — Cluster support for shared state synchronization.
#
# Architecture:
#   Worker detects campaign email → updates local state tables →
#   publishes update event to a proxy via Cluster::publish_hrw →
#   proxy updates authoritative state → broadcasts to all workers →
#   workers update local cache.
#
# Tables synchronized:
#   - learned_bad_senders, learned_bad_subjects
#   - tracked_campaign_senders, tracked_campaign_msg_ids, tracked_campaign_subjects
#   - campaign_contact_pairs
#   - conversation_states
#
# Tables NOT needing cluster code (handled automatically):
#   - SumStats (spray, wave) — framework handles cluster natively
#   - Intel framework — handles cluster natively

@load base/frameworks/cluster

module SocialEngineering;

export {
    ## Cluster events for state synchronization.
    ## Workers publish these to proxies; proxies broadcast to workers.

    ## Sync learned IOCs (sender address + subject) from CampaignMatch.
    global cluster_learned_ioc: event(sender: string, subject: string);

    ## Sync tracked campaign email attributes for reply detection.
    global cluster_track_campaign: event(sender: string, msg_id: string,
                                         subject: string);

    ## Sync sender→recipient contact pair for follow-up escalation.
    global cluster_contact_pair: event(sender: string, recipient: string);

    ## Sync conversation state transition.
    global cluster_conv_state: event(key: string, state: ConversationState);
}

# -----------------------------------------------------------------------
# CLUSTER-AWARE WRAPPER FUNCTIONS
#
# These replace direct state mutations in detection.zeek.
# In standalone mode: update local state only.
# In cluster mode: update local state + publish to proxy.
# -----------------------------------------------------------------------

function cluster_add_learned_ioc(sender: string, subject: string)
    {
    # Update local state immediately (worker needs it for current session)
    if ( sender != "" )
        add learned_bad_senders[sender];
    if ( subject != "" )
        add learned_bad_subjects[normalize_subject(subject)];

@if ( Cluster::is_enabled() )
    local key = sender != "" ? sender : subject;
    local topic = Cluster::hrw_topic(Cluster::proxy_pool, key);
    if ( topic != "" )
        Broker::publish(topic, Broker::make_event(
            SocialEngineering::cluster_learned_ioc,
            sender, subject));
@endif
    }

function cluster_add_track_campaign(sender: string, msg_id: string,
                                     subject: string)
    {
    # Update local state
    if ( sender != "" )
        add tracked_campaign_senders[sender];
    if ( msg_id != "" )
        add tracked_campaign_msg_ids[msg_id];
    if ( subject != "" )
        add tracked_campaign_subjects[normalize_subject(subject)];

@if ( Cluster::is_enabled() )
    local key = sender != "" ? sender : msg_id;
    local topic = Cluster::hrw_topic(Cluster::proxy_pool, key);
    if ( topic != "" )
        Broker::publish(topic, Broker::make_event(
            SocialEngineering::cluster_track_campaign,
            sender, msg_id, subject));
@endif
    }

function cluster_add_contact_pair(sender: string, recipient: string)
    {
    # Update local state
    if ( sender !in campaign_contact_pairs )
        campaign_contact_pairs[sender] = set();
    add campaign_contact_pairs[sender][recipient];

@if ( Cluster::is_enabled() )
    local topic = Cluster::hrw_topic(Cluster::proxy_pool, sender);
    if ( topic != "" )
        Broker::publish(topic, Broker::make_event(
            SocialEngineering::cluster_contact_pair,
            sender, recipient));
@endif
    }

function cluster_set_conv_state(key: string, state: ConversationState)
    {
    # Update local state
    conversation_states[key] = state;

@if ( Cluster::is_enabled() )
    local topic = Cluster::hrw_topic(Cluster::proxy_pool, key);
    if ( topic != "" )
        Broker::publish(topic, Broker::make_event(
            SocialEngineering::cluster_conv_state,
            key, state));
@endif
    }

# -----------------------------------------------------------------------
# PROXY-SIDE HANDLERS
#
# Receive updates from workers, update authoritative state,
# broadcast to all workers so every node has a consistent view.
# -----------------------------------------------------------------------

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::PROXY )

event SocialEngineering::cluster_learned_ioc(sender: string, subject: string)
    {
    if ( sender != "" )
        add learned_bad_senders[sender];
    if ( subject != "" )
        add learned_bad_subjects[normalize_subject(subject)];

    # Broadcast to all workers
    Broker::publish(Cluster::worker_topic, Broker::make_event(
        SocialEngineering::cluster_learned_ioc,
        sender, subject));
    }

event SocialEngineering::cluster_track_campaign(sender: string, msg_id: string,
                                                 subject: string)
    {
    if ( sender != "" )
        add tracked_campaign_senders[sender];
    if ( msg_id != "" )
        add tracked_campaign_msg_ids[msg_id];
    if ( subject != "" )
        add tracked_campaign_subjects[normalize_subject(subject)];

    Broker::publish(Cluster::worker_topic, Broker::make_event(
        SocialEngineering::cluster_track_campaign,
        sender, msg_id, subject));
    }

event SocialEngineering::cluster_contact_pair(sender: string, recipient: string)
    {
    if ( sender !in campaign_contact_pairs )
        campaign_contact_pairs[sender] = set();
    add campaign_contact_pairs[sender][recipient];

    Broker::publish(Cluster::worker_topic, Broker::make_event(
        SocialEngineering::cluster_contact_pair,
        sender, recipient));
    }

event SocialEngineering::cluster_conv_state(key: string, state: ConversationState)
    {
    conversation_states[key] = state;

    Broker::publish(Cluster::worker_topic, Broker::make_event(
        SocialEngineering::cluster_conv_state,
        key, state));
    }

@endif

# -----------------------------------------------------------------------
# WORKER-SIDE HANDLERS
#
# Receive broadcasts from proxy and update local cache.
# These fire when ANOTHER worker's detection results are propagated.
# The originating worker already updated its own local state in the
# wrapper function, so these are idempotent (set adds are no-ops
# if already present).
# -----------------------------------------------------------------------

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER )

event SocialEngineering::cluster_learned_ioc(sender: string, subject: string)
    {
    if ( sender != "" )
        add learned_bad_senders[sender];
    if ( subject != "" )
        add learned_bad_subjects[normalize_subject(subject)];
    }

event SocialEngineering::cluster_track_campaign(sender: string, msg_id: string,
                                                 subject: string)
    {
    if ( sender != "" )
        add tracked_campaign_senders[sender];
    if ( msg_id != "" )
        add tracked_campaign_msg_ids[msg_id];
    if ( subject != "" )
        add tracked_campaign_subjects[normalize_subject(subject)];
    }

event SocialEngineering::cluster_contact_pair(sender: string, recipient: string)
    {
    if ( sender !in campaign_contact_pairs )
        campaign_contact_pairs[sender] = set();
    add campaign_contact_pairs[sender][recipient];
    }

event SocialEngineering::cluster_conv_state(key: string, state: ConversationState)
    {
    conversation_states[key] = state;
    }

@endif
