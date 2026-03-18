# detection.zeek — Event handlers for social engineering campaign detection.
#
# Layers:
#   1. Known sender IOC matching (FROM header)
#   2. Subject pattern matching (SUBJECT header)
#   3. Body content accumulation (MIME entity data)
#   4. Score evaluation at message end (smtp_reply)
#   5. Sender spray detection (SumStats)
#   6. Reply detection (outbound to tracked campaign senders)

module SocialEngineering;

# ---------------------------------------------------------------------------
# EVENT HANDLERS
# ---------------------------------------------------------------------------

# --- Layer 1: Known sender IOC matching ---

event mime_one_header(c: connection, h: mime_header_rec) &priority=4
    {
    if ( ! c?$smtp )
        return;

    init_conn_state(c$uid);

    # --- Combined FROM header processing: reply tracking + IOC matching ---
    if ( h$name == "FROM" )
        {
        local sender_addrs = extract_email_addrs_set(h$value);
        local from_lower = to_lower(h$value);

        # Capture first sender address for reply detection
        for ( sa in sender_addrs )
            {
            conn_from_addr[c$uid] = to_lower(sa);
            break;
            }

        # Check exact sender addresses against IOC list
        for ( ea in sender_addrs )
            {
            if ( to_lower(ea) in known_bad_senders )
                {
                conn_sender_ioc[c$uid] = T;
                conn_scores[c$uid] += 10.0;
                conn_matched[c$uid] += "KNOWN_SENDER_IOC";

                NOTICE([$note=KnownSender,
                        $msg=fmt("Known SE campaign sender: %s", ea),
                        $sub=fmt("From: %s", h$value),
                        $conn=c,
                        $identifier=cat(c$uid)]);
                }
            }

        # Check sender addresses against pattern-based IOCs
        if ( ! conn_sender_ioc[c$uid] )
            {
            for ( ea2 in sender_addrs )
                {
                local ea2_lower = to_lower(ea2);
                for ( sp in known_bad_sender_patterns )
                    {
                    if ( sp == ea2_lower )
                        {
                        conn_sender_ioc[c$uid] = T;
                        conn_scores[c$uid] += 10.0;
                        conn_matched[c$uid] += fmt("SENDER_PATTERN:%s", ea2_lower);

                        NOTICE([$note=KnownSender,
                                $msg=fmt("SE campaign sender pattern match: %s", ea2),
                                $sub=fmt("From: %s", h$value),
                                $conn=c,
                                $identifier=cat(c$uid)]);
                        break;
                        }
                    }
                if ( conn_sender_ioc[c$uid] )
                    break;
                }
            }

        # Check sender addresses against learned IOCs (from prior CampaignMatch)
        if ( ! conn_sender_ioc[c$uid] )
            {
            for ( ea3 in sender_addrs )
                {
                if ( to_lower(ea3) in learned_bad_senders )
                    {
                    conn_sender_ioc[c$uid] = T;
                    conn_scores[c$uid] += 5.0;
                    conn_matched[c$uid] += fmt("LEARNED_SENDER:%s", to_lower(ea3));

                    NOTICE([$note=KnownSender,
                            $msg=fmt("SE campaign learned sender: %s (from prior CampaignMatch)", ea3),
                            $sub=fmt("From: %s", h$value),
                            $conn=c,
                            $identifier=cat(c$uid)]);
                    break;
                    }
                }
            }

        # Check display name substrings
        local addr_already_matched = conn_sender_ioc[c$uid];
        for ( dn in known_bad_display_names )
            {
            if ( to_lower(dn) in from_lower )
                {
                conn_sender_ioc[c$uid] = T;
                conn_scores[c$uid] += 5.0;

                if ( ! addr_already_matched )
                    {
                    # Display name reuse: known persona, unrecognized address
                    local dn_sender = "";
                    for ( dns in sender_addrs )
                        { dn_sender = to_lower(dns); break; }
                    local dn_domain = get_email_domain(dn_sender);
                    if ( dn_domain != "" && dn_domain !in internal_mail_domains )
                        {
                        conn_matched[c$uid] += fmt("DISPLAY_NAME_NEW_ADDR:%s", dn);

                        NOTICE([$note=DisplayNameReuse,
                                $msg=fmt("Known SE display name '%s' with unrecognized sender: %s", dn, dn_sender),
                                $sub=fmt("From: %s", h$value),
                                $conn=c,
                                $identifier=cat(c$uid)]);
                        }
                    else
                        conn_matched[c$uid] += fmt("DISPLAY_NAME:%s", dn);
                    }
                else
                    conn_matched[c$uid] += fmt("DISPLAY_NAME:%s", dn);
                }
            }
        }

    # --- SUBJECT header processing: static patterns + learned subjects ---
    if ( h$name == "SUBJECT" )
        {
        local subj_val = h$value;

        # Check against static subject patterns
        for ( sp2 in subject_patterns )
            {
            if ( sp2 in subj_val )
                {
                conn_subject_ioc[c$uid] = T;
                conn_scores[c$uid] += 3.0;
                conn_matched[c$uid] += fmt("SUBJECT_PATTERN:%s", subj_val);

                NOTICE([$note=SubjectMatch,
                        $msg=fmt("SE campaign subject pattern match: %s", subj_val),
                        $sub=fmt("Subject: %s", subj_val),
                        $conn=c,
                        $identifier=cat(c$uid)]);
                break;
                }
            }

        # Check against learned subjects (from prior CampaignMatch)
        if ( ! conn_subject_ioc[c$uid] )
            {
            local norm_subj2 = normalize_subject(subj_val);
            if ( norm_subj2 in learned_bad_subjects )
                {
                conn_subject_ioc[c$uid] = T;
                conn_scores[c$uid] += 3.0;
                conn_matched[c$uid] += fmt("LEARNED_SUBJECT:%s", subj_val);

                NOTICE([$note=SubjectMatch,
                        $msg=fmt("SE campaign learned subject match: %s (from prior CampaignMatch)", subj_val),
                        $sub=fmt("Subject: %s", subj_val),
                        $conn=c,
                        $identifier=cat(c$uid)]);
                }
            }
        }

    # --- CONTENT-TYPE / CONTENT-DISPOSITION for MIME fingerprinting ---
    if ( c$uid !in conn_mime_fp )
        conn_mime_fp[c$uid] = MimeFingerprint();

    if ( h$name == "CONTENT-TYPE" )
        {
        local ct_lower = to_lower(h$value);
        if ( /multipart\// in ct_lower )
            conn_mime_fp[c$uid]$has_multipart = T;
        if ( /text\/html/ in ct_lower )
            conn_mime_fp[c$uid]$has_html = T;
        }

    if ( h$name == "CONTENT-DISPOSITION" )
        {
        if ( /attachment/ in to_lower(h$value) )
            conn_mime_fp[c$uid]$has_attachment = T;
        }
    }

# --- MIME structure fingerprinting ---

event mime_begin_entity(c: connection)
    {
    if ( ! c?$smtp )
        return;

    if ( c$uid !in conn_mime_fp )
        conn_mime_fp[c$uid] = MimeFingerprint();

    ++conn_mime_fp[c$uid]$entity_count;
    }

# --- Layer 3: Body content accumulation and scoring ---

event mime_entity_data(c: connection, length: count, data: string)
    {
    if ( ! c?$smtp )
        return;

    init_conn_state(c$uid);

    # Accumulate body content (cap at 32KB to avoid memory issues)
    if ( |conn_body[c$uid]| < 32768 )
        conn_body[c$uid] += data;
    }

# --- Layer 4: Score evaluation at message end ---

event mime_all_headers(c: connection, hlist: mime_header_list)
    {
    # This is a good checkpoint but body scoring happens at smtp_reply
    # when the full message has been received
    }

# Evaluate accumulated body content when SMTP transaction completes.
# Also performs reply detection for outbound messages.
# Priority -4 ensures we run BEFORE Zeek's built-in handler at -5
# which resets c$smtp state via smtp_message().
event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=-4
    {
    # Only process on successful message acceptance (250 response to DATA/.)
    # BDAT (chunked transfer) produces cmd="(UNKNOWN)" for the final 250,
    # so we also accept (UNKNOWN) — guarded below by requiring message data.
    if ( code != 250 )
        return;

    if ( cmd != "." && cmd != "BDAT" )
        {
        # For non-standard cmd values (e.g. BDAT showing as "(UNKNOWN)"),
        # only proceed if we have accumulated message data (FROM header seen).
        if ( c$uid !in conn_from_addr && c$uid !in conn_body )
            return;
        # Skip known non-message commands that return 250
        if ( cmd == "EHLO" || cmd == "HELO" || cmd == "MAIL" || cmd == "RCPT"
             || cmd == "RSET" || cmd == "NOOP" || cmd == "VRFY" )
            return;
        }

    if ( ! c?$smtp )
        return;

    init_conn_state(c$uid);

    local body = conn_body[c$uid];
    local sender = get_sender_addr(c);
    local subject = get_subject(c);

    # =======================================================================
    # LAYER 6: REPLY DETECTION — is this an internal user replying to a
    # previously detected campaign email?
    # =======================================================================

    local is_internal = F;
    if ( c$uid in conn_from_addr )
        is_internal = is_internal_sender(conn_from_addr[c$uid]);

    if ( is_internal && c$smtp?$rcptto )
        {
        local reply_detected = F;
        local reply_reason = "";
        local reply_recipient = "";

        for ( rcpt in c$smtp$rcptto )
            {
            local rcpt_lower = to_lower(rcpt);

            # Method 1: Recipient is a tracked campaign sender
            if ( rcpt_lower in tracked_campaign_senders )
                {
                reply_detected = T;
                reply_recipient = rcpt_lower;
                reply_reason = fmt("RCPT_TO matches tracked campaign sender: %s", rcpt_lower);
                break;
                }

            # Method 1b: Recipient is a known bad sender IOC
            if ( rcpt_lower in known_bad_senders )
                {
                reply_detected = T;
                reply_recipient = rcpt_lower;
                reply_reason = fmt("RCPT_TO matches known bad sender IOC: %s", rcpt_lower);
                break;
                }

            # Method 1c: Recipient matches a known bad sender pattern
            for ( rp in known_bad_sender_patterns )
                {
                if ( rp == rcpt_lower )
                    {
                    reply_detected = T;
                    reply_recipient = rcpt_lower;
                    reply_reason = fmt("RCPT_TO matches known bad sender pattern: %s", rcpt_lower);
                    break;
                    }
                }

            # Method 1d: Recipient is a learned bad sender (from prior CampaignMatch)
            if ( ! reply_detected && rcpt_lower in learned_bad_senders )
                {
                reply_detected = T;
                reply_recipient = rcpt_lower;
                reply_reason = fmt("RCPT_TO matches learned campaign sender: %s", rcpt_lower);
                }

            if ( reply_detected )
                break;
            }

        # Method 2: In-Reply-To matches a tracked campaign Message-ID
        if ( ! reply_detected && c$uid in conn_in_reply_to )
            {
            if ( conn_in_reply_to[c$uid] in tracked_campaign_msg_ids )
                {
                reply_detected = T;
                reply_reason = fmt("In-Reply-To matches tracked campaign Message-ID: %s",
                                   conn_in_reply_to[c$uid]);
                }
            }

        # Method 3: Subject is a reply to a tracked campaign subject
        if ( ! reply_detected && subject != "" )
            {
            local norm_subj = normalize_subject(subject);
            if ( /^re:/i in to_lower(subject) && norm_subj in tracked_campaign_subjects )
                {
                # Only flag if recipient domain is external (not internal-to-internal)
                for ( r2 in c$smtp$rcptto )
                    {
                    if ( ! is_internal_sender(to_lower(r2)) )
                        {
                        reply_detected = T;
                        reply_recipient = to_lower(r2);
                        reply_reason = fmt("Subject 'Re:' matches tracked campaign subject, external rcpt: %s",
                                           reply_recipient);
                        break;
                        }
                    }
                }
            }

        if ( reply_detected )
            {
            local internal_sender = c$uid in conn_from_addr ? conn_from_addr[c$uid] : sender;

            NOTICE([$note=VictimReply,
                    $msg=fmt("CRITICAL: Internal user replied to SE campaign email. Victim: %s | Detection: %s",
                             internal_sender, reply_reason),
                    $sub=fmt("From: %s | To: %s | Subject: %s",
                             internal_sender,
                             reply_recipient != "" ? reply_recipient : "unknown",
                             subject),
                    $conn=c,
                    $identifier=fmt("%s-%s", internal_sender, reply_recipient)]);

            write_campaign_log(c, internal_sender, subject, 0.0,
                               reply_reason, "VictimReply", F);

            # Transition conversation state: attacker→victim → VICTIM_REPLIED
            # Cluster-aware: updates local state + publishes to proxy.
            if ( reply_recipient != "" )
                {
                local vr_key = fmt("%s,%s", reply_recipient, internal_sender);
                cluster_set_conv_state(vr_key, VICTIM_REPLIED);
                }
            }
        }

    # =======================================================================
    # CONVERSATION ESCALATION — attacker following up after victim replied
    # =======================================================================

    local conv_escalated = F;
    if ( sender != "" && c$smtp?$rcptto )
        {
        for ( ce_rcpt in c$smtp$rcptto )
            {
            local ce_key = fmt("%s,%s", sender, to_lower(ce_rcpt));
            if ( ce_key in conversation_states
                 && conversation_states[ce_key] == VICTIM_REPLIED )
                {
                conv_escalated = T;
                cluster_set_conv_state(ce_key, ATTACKER_FOLLOWUP);
                conn_matched[c$uid] += fmt("CONVERSATION_ESCALATION:%s->%s", sender, to_lower(ce_rcpt));

                NOTICE([$note=ConversationEscalation,
                        $msg=fmt("CRITICAL: Active attacker-victim conversation. Attacker %s is following up with victim %s who previously replied",
                                 sender, to_lower(ce_rcpt)),
                        $sub=fmt("From: %s | To: %s | Subject: %s",
                                 sender, to_lower(ce_rcpt), subject),
                        $conn=c,
                        $identifier=fmt("conv-%s-%s", sender, to_lower(ce_rcpt))]);

                write_campaign_log(c, sender, subject, conn_scores[c$uid],
                                   fmt("CONVERSATION_ESCALATION:%s->%s", sender, to_lower(ce_rcpt)),
                                   "ConversationEscalation", F);
                break;
                }
            }
        }

    # =======================================================================
    # FOLLOW-UP ESCALATION — repeated contact from a campaign sender
    # (skipped if ConversationEscalation already fired — doesn't stack)
    # =======================================================================

    if ( ! conv_escalated && sender != ""
         && sender in campaign_contact_pairs && c$smtp?$rcptto )
        {
        for ( fu_rcpt in c$smtp$rcptto )
            {
            if ( to_lower(fu_rcpt) in campaign_contact_pairs[sender] )
                {
                conn_scores[c$uid] += 5.0;
                conn_matched[c$uid] += fmt("FOLLOW_UP_CONTACT:%s->%s", sender, to_lower(fu_rcpt));
                break;
                }
            }
        }

    # =======================================================================
    # LAYERS 3-4: BODY SCORING (inbound campaign detection)
    # =======================================================================

    # Score body against all indicators
    if ( |body| > 0 )
        {
        for ( i in body_indicators )
            {
            local indicator = body_indicators[i];
            if ( indicator$pattern_match in body )
                {
                conn_scores[c$uid] += indicator$weight;
                conn_matched[c$uid] += indicator$description;
                }
            }
        }

    # =======================================================================
    # STRUCTURAL AMPLIFIERS — only fire when score > 0 (amplifier gate)
    # =======================================================================

    if ( conn_scores[c$uid] > 0.0 )
        {
        # MIME structure: plain text only, no multipart, no HTML, no attachments
        if ( c$uid in conn_mime_fp )
            {
            local fp = conn_mime_fp[c$uid];
            if ( fp$entity_count <= 1 && ! fp$has_multipart
                 && ! fp$has_html && ! fp$has_attachment )
                {
                conn_scores[c$uid] += 1.0;
                conn_matched[c$uid] += "PLAIN_TEXT_STRUCTURE";
                }
            }

        # Sender address entropy: high numeric density in freemail local-part
        if ( sender != "" )
            {
            local sender_domain = get_email_domain(sender);
            if ( sender_domain in freemail_domains )
                {
                local ratio = local_part_numeric_ratio(sender);
                if ( ratio >= entropy_numeric_ratio )
                    {
                    conn_scores[c$uid] += 1.0;
                    conn_matched[c$uid] += fmt("HIGH_SENDER_ENTROPY:%.0f%%", ratio * 100.0);
                    }
                }
            }

        # No links and no attachments: unusual for cold outreach
        local has_url = F;
        if ( |body| > 0 )
            {
            if ( /https?:\/\// in body || /www\./ in body )
                has_url = T;
            }
        local has_attach = c$uid in conn_mime_fp ?
                           conn_mime_fp[c$uid]$has_attachment : F;

        if ( ! has_url && ! has_attach )
            {
            conn_scores[c$uid] += 1.0;
            conn_matched[c$uid] += "NO_LINKS_OR_ATTACHMENTS";
            }
        }

    local score = conn_scores[c$uid];

    # Build matched indicators string for notice
    local matched_str = "";
    for ( j in conn_matched[c$uid] )
        {
        if ( |matched_str| > 0 )
            matched_str += " | ";
        matched_str += conn_matched[c$uid][j];
        }

    # Fire body indicators notice if threshold exceeded
    if ( score >= body_score_threshold )
        {
        NOTICE([$note=BodyIndicators,
                $msg=fmt("SE campaign body indicators detected (score=%.1f): %s",
                         score, matched_str),
                $sub=fmt("From: %s | Subject: %s", sender, subject),
                $conn=c,
                $identifier=cat(c$uid)]);

        write_campaign_log(c, sender, subject, score, matched_str,
                           "BodyIndicators", F);
        }

    # Fire high-confidence campaign match if combined threshold exceeded
    if ( score >= campaign_score_threshold )
        {
        NOTICE([$note=CampaignMatch,
                $msg=fmt("HIGH CONFIDENCE: SE campaign email detected (score=%.1f/%s indicators)",
                         score, |conn_matched[c$uid]|),
                $sub=fmt("From: %s | To: %s | Subject: %s",
                         sender,
                         c$smtp?$rcptto ? cat(c$smtp$rcptto) : "unknown",
                         subject),
                $conn=c,
                $suppress_for=1hr,
                $identifier=fmt("campaign-%s", normalize_subject_for_suppress(subject))]);

        local cm_is_learned = F;
        for ( cm_idx in conn_matched[c$uid] )
            {
            if ( /^LEARNED_/ in conn_matched[c$uid][cm_idx] )
                { cm_is_learned = T; break; }
            }

        write_campaign_log(c, sender, subject, score, matched_str,
                           "CampaignMatch", cm_is_learned);

        # Auto-learn sender and subject as runtime IOCs for pivoting.
        # Future emails from this sender or with this subject are
        # immediately flagged without needing a static IOC/pattern.
        #
        # GUARDS (all must pass to learn):
        #   1. Not internal — internal users are never campaign senders
        #   2. Freemail sender — the campaign uses disposable freemail
        #      addresses. Branded-domain senders (mailing lists, SaaS,
        #      forwarding relays like ops@lists.ren-isac.net) must NOT
        #      be learned, as doing so causes cascading false positives
        #      on every subsequent email from that infrastructure address.
        #   3. Subject is always learned (when sender qualifies) because
        #      the campaign reuses subjects across disposable senders.
        #
        # Cluster-aware: updates local state + publishes to proxy.
        if ( ! is_internal && sender != "" )
            {
            local learn_domain = get_email_domain(sender);
            if ( learn_domain in freemail_domains )
                cluster_add_learned_ioc(sender, subject);
            }

        if ( sender != "" && ! is_internal )
            {
            # Feed into Intel framework for cross-script visibility.
            # Only external senders — internal users are never campaign senders.
            insert_intel_indicator(sender, Intel::EMAIL,
                                   fmt("SE campaign sender (score=%.1f)", score));
            }

        # Record sender→recipient pairs for follow-up escalation.
        # If the same sender contacts the same recipient again, the
        # follow-up check (above body scoring) boosts the score.
        # GUARD: Only track external senders as campaign attackers.
        # Internal users whose replies score above threshold must not
        # be recorded as attackers in the contact/conversation tables.
        # Cluster-aware: updates local state + publishes to proxy.
        if ( sender != "" && ! is_internal && c$smtp?$rcptto )
            {
            for ( cp_rcpt in c$smtp$rcptto )
                {
                cluster_add_contact_pair(sender, to_lower(cp_rcpt));

                # Initialize conversation state: attacker → victim
                local cs_key = fmt("%s,%s", sender, to_lower(cp_rcpt));
                if ( cs_key !in conversation_states )
                    cluster_set_conv_state(cs_key, CAMPAIGN_SENT);
                }
            }

        # VIP target check — escalate if any recipient is high-value
        if ( c$smtp?$rcptto && |high_value_targets| > 0 )
            {
            for ( vip_rcpt in c$smtp$rcptto )
                {
                if ( to_lower(vip_rcpt) in high_value_targets )
                    {
                    NOTICE([$note=VIPTargeted,
                            $msg=fmt("CRITICAL: SE campaign email targeted VIP: %s",
                                     vip_rcpt),
                            $sub=fmt("From: %s | VIP: %s | Subject: %s",
                                     sender, vip_rcpt, subject),
                            $conn=c,
                            $identifier=fmt("%s-%s", sender, vip_rcpt)]);

                    write_campaign_log(c, sender, subject, score, matched_str,
                                       "VIPTargeted", cm_is_learned);
                    break;
                    }
                }
            }

        # Feed matched display names into campaign wave SumStats.
        # Key = display name, observation = unique sender address.
        # Skip internal senders — wave detection is for external attacks.
        if ( sender != "" && ! is_internal )
            {
            for ( wave_idx in conn_matched[c$uid] )
                {
                local wave_m = conn_matched[c$uid][wave_idx];
                if ( /^DISPLAY_NAME/ in wave_m )
                    {
                    # Extract display name from "DISPLAY_NAME:Xxx" or
                    # "DISPLAY_NAME_NEW_ADDR:Xxx"
                    local wave_parts = split_string(wave_m, /:/);
                    if ( |wave_parts| >= 2 )
                        {
                        SumStats::observe("se.campaign_wave",
                                          SumStats::Key($str=wave_parts[1]),
                                          SumStats::Observation($str=sender));
                        }
                    }
                }
            }
        }

    # =======================================================================
    # INTERNAL FORWARDING DETECTION — internal user forwarding campaign email
    # =======================================================================

    if ( is_internal && score >= body_score_threshold
         && /^(fwd|fw):/i in to_lower(subject) )
        {
        local fwd_sender = c$uid in conn_from_addr ? conn_from_addr[c$uid] : sender;
        local fwd_rcpts = c$smtp?$rcptto ? cat(c$smtp$rcptto) : "unknown";

        NOTICE([$note=InternalForwarding,
                $msg=fmt("Internal user forwarded SE campaign email. Forwarder: %s (score=%.1f)",
                         fwd_sender, score),
                $sub=fmt("From: %s | To: %s | Subject: %s",
                         fwd_sender, fwd_rcpts, subject),
                $conn=c,
                $identifier=fmt("fwd-%s-%s", fwd_sender, subject)]);

        write_campaign_log(c, fwd_sender, subject, score, matched_str,
                           "InternalForwarding", F);
        }

    # =======================================================================
    # TRACK DETECTED CAMPAIGN EMAILS FOR FUTURE REPLY DETECTION
    # =======================================================================

    # GUARD: Only track external senders for reply detection. Internal
    # users whose replies happen to score above threshold (e.g., via
    # subject pattern + body indicator) must not be added to the
    # tracked_campaign_senders set — doing so causes any subsequent
    # email TO that internal user to fire a false VictimReply.
    if ( ! is_internal && ( score >= body_score_threshold || conn_sender_ioc[c$uid] ) )
        {
        local campaign_sender = sender;
        local campaign_msg_id = c$uid in conn_msg_id ? conn_msg_id[c$uid] : "";
        track_campaign_email(campaign_sender, campaign_msg_id, subject);
        }

    # =======================================================================
    # LAYER 5: SENDER SPRAY SUMSTATS FEED
    # =======================================================================

    # Feed sender into SumStats for spray detection.
    # Only track freemail senders — the campaign uses disposable freemail
    # addresses (gmail, yahoo, etc). Branded-domain senders (newsletters,
    # SaaS notifications, nagios) are never campaign spray and generate
    # massive false positives at low thresholds.
    if ( sender != "" && ! is_internal )
        {
        local spray_domain = get_email_domain(sender);
        if ( spray_domain in freemail_domains )
            {
            local rcpts: set[string];
            if ( c$smtp?$rcptto )
                rcpts = c$smtp$rcptto;
            else
                rcpts = set("");

            for ( rcpt in rcpts )
                {
                SumStats::observe("lbnl_se.sender_spray",
                                  SumStats::Key($str=sender),
                                  SumStats::Observation($str=rcpt));
                }
            }
        }

    # Cleanup connection state
    delete conn_body[c$uid];
    delete conn_scores[c$uid];
    delete conn_matched[c$uid];
    delete conn_sender_ioc[c$uid];
    delete conn_subject_ioc[c$uid];
    if ( c$uid in conn_mime_fp )
        delete conn_mime_fp[c$uid];
    if ( c$uid in conn_from_addr )
        delete conn_from_addr[c$uid];
    if ( c$uid in conn_in_reply_to )
        delete conn_in_reply_to[c$uid];
    if ( c$uid in conn_msg_id )
        delete conn_msg_id[c$uid];
    }

# ---------------------------------------------------------------------------
# SUMSTATS: SENDER SPRAY DETECTION
# ---------------------------------------------------------------------------

event zeek_init()
    {
    # --- SumStats for spray detection ---
    local r1 = SumStats::Reducer($stream="lbnl_se.sender_spray",
                                  $apply=set(SumStats::UNIQUE));

    SumStats::create([$name="lbnl-se-spray-detection",
                      $epoch=spray_window,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          return result["lbnl_se.sender_spray"]$unique + 0.0;
                          },
                      $threshold=spray_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          NOTICE([$note=SenderSpray,
                                  $msg=fmt("External sender emailed %.0f+ unique recipients in %s (spray pattern)",
                                           spray_threshold, spray_window),
                                   $sub=fmt("Sender: %s | Unique recipients: %d",
                                            key$str,
                                            result["lbnl_se.sender_spray"]$unique),
                                  $identifier=key$str]);
                          }]);

    # --- SumStats for campaign wave detection ---
    # Detects multiple unique sender addresses using the same display name
    # within a time window — indicates an active coordinated campaign wave.
    local r2 = SumStats::Reducer($stream="se.campaign_wave",
                                  $apply=set(SumStats::UNIQUE));

    SumStats::create([$name="se-campaign-wave-detection",
                      $epoch=wave_window,
                      $reducers=set(r2),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          return result["se.campaign_wave"]$unique + 0.0;
                          },
                      $threshold=wave_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          NOTICE([$note=CampaignWave,
                                  $msg=fmt("Campaign wave detected: %.0f+ unique senders using display name '%s' in %s",
                                           wave_threshold, key$str, wave_window),
                                  $sub=fmt("Display name: %s | Unique senders: %d",
                                           key$str,
                                           result["se.campaign_wave"]$unique),
                                  $identifier=fmt("wave-%s", key$str)]);
                          }]);
    }

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == VictimReply )
        {
        add n$actions[Notice::ACTION_EMAIL];
        add n$email_dest[alert_email_dest];
        }

    if ( n$note == CampaignMatch )
        {
        add n$actions[Notice::ACTION_EMAIL];
        add n$email_dest[alert_email_dest];
        }

    if ( n$note == VIPTargeted )
        {
        add n$actions[Notice::ACTION_EMAIL];
        add n$email_dest[alert_email_dest];
        }

    # SenderSpray: log only, no email — too noisy for email alerting.
    # Spray is now gated to freemail senders only, so it's informational.

    if ( n$note == ConversationEscalation )
        {
        add n$actions[Notice::ACTION_EMAIL];
        add n$email_dest[alert_email_dest];
        }
    }
