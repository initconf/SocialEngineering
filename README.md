# SocialEngineering

A multi-layered Zeek package for detecting a coordinated social engineering campaign targeting research institutions. Built from real-world threat intelligence gathered from 120+ phishing emails that used fabricated personas to target 45+ scientists, engineers, and operational staff at research institution.

The package goes beyond simple IOC matching — it scores email bodies against 20 behavioral indicators extracted from the campaign corpus, tracks detected campaign emails across sessions, detects campaign waves using disposable addresses, tracks full attacker-victim conversation lifecycles, and **alerts in real time when an internal user replies to or forwards a phishing email**.

## Threat Background

The campaign uses two fabricated personas:

| Persona | Claimed Background | Targeting |
|---|---|---|
| **Amy Bloom** | Monaco upbringing, design in Paris, finance in the US. "Private art collections, long-term investment structures, scientific philanthropy." | Senior scientists, lab leadership, high-profile researchers |
| **Lillian Briger** | Brunei upbringing, business administration at Stanford. "Advising royal families on next-generation education planning." | Operations staff, facility managers, policy researchers |

Both personas send hyper-personalized emails referencing the target's specific research, ask flattering binary questions ("Will the biggest breakthroughs come from X or Y?"), and close with low-commitment requests ("If you ever have a moment to share a quick thought..."). The emails contain **no malicious links or attachments** — they are pure social engineering designed to open a communication channel for later exploitation.

At least one target was successfully compromised: a retired scientist shared his personal email, cell phone number, physical location, and offered to meet the attacker in person.

## Detection Architecture

```
                    ┌─────────────────────────────────────────────────┐
  Inbound Email ───>│  Layer 1: Known Sender IOCs (address + name)    │
                    │  Layer 1b: Sender Pattern Matching (regex)      │
                    │  Layer 1c: Learned Sender IOCs (auto-pivoting)  │
                    │  Layer 1d: Display Name Reuse Detection         │
                    │  Layer 2: Subject Line Pattern Matching         │
                    │  Layer 2b: Learned Subject IOCs (auto-pivoting) │
                    │  Layer 3: Body Content Scoring (20 indicators)  │
                    │  Layer 3b: Structural Amplifiers                │
                    │     - MIME fingerprint (plain text only)        │
                    │     - Sender address entropy (freemail)         │
                    │     - No links/attachments signal               │
                    │  Layer 4: Combined Score Threshold              │
                    │  Layer 5: Follow-Up Escalation (+5.0 boost)     │
                    │  Layer 6: Conversation State Tracking           │
                    └──────────────┬──────────────────────────────────┘
                                   │
                         Score >= campaign threshold?
                                   │
                         ┌─────────▼──────────┐
                         │  AUTO-LEARN IOCs   │  sender -> learned_bad_senders
                         │  + Intel feed      │  subject -> learned_bad_subjects
                         │  + Contact pairs   │  sender,rcpt -> contact_pairs
                         │  + Conversation    │  sender,rcpt -> CAMPAIGN_SENT
                         └─────────┬──────────┘
                                   │
                   ┌────────────────▼──────────────────────────────────────┐
                   │  SumStats Detection                                   │
                   │    - Sender Spray: freemail -> 500+ recipients (24h)  │
                   │    - Campaign Wave: 3+ senders same persona (1h)     │
                   └────────────────┬──────────────────────────────────────┘
                                   │
                              ┌────▼─────┐
                              │  TRACK   │  sender, Message-ID, subject
                              │  for     │  stored for 90 days
                              │  replies │
                              └────┬─────┘
                                   │
                    ┌──────────────▼──────────────────────────────────┐
  Outbound Email -->│  Layer 7: Reply Detection                       │
                    │    - Recipient matches tracked campaign sender  │
                    │    - Recipient matches learned campaign sender  │
                    │    - In-Reply-To matches tracked Message-ID     │
                    │    - "Re:" subject matches tracked subject      │
                    │  Layer 8: Internal Forwarding Detection          │
                    │    - "Fwd:" subject + body score >= threshold   │
                    └────────────────────────┬───────────────────────-┘
                                             │
                    ┌────────────────────────▼──────────────────────────┐
                    │  Conversation State Machine                       │
                    │    CAMPAIGN_SENT -> VICTIM_REPLIED ->             │
                    │    ATTACKER_FOLLOWUP (fires ConversationEscalation)│
                    └────────────────────────┬──────────────────────────┘
                                             │
                                       ┌─────▼───────┐
                                       │ EMAIL ALERT │
                                       │ to SOC/CI   │
                                       └─────────────┘
```

### Notice Types

| Notice | Severity | Trigger | Email Alert |
|---|---|---|---|
| `KnownSender` | High | Sender address, display name, pattern, or learned IOC matches | No |
| `SubjectMatch` | Medium | Subject line matches campaign regex pattern or learned subject | No |
| `BodyIndicators` | High | Body content score exceeds body threshold (default: 6.0) | No |
| `CampaignMatch` | **Critical** | Combined score exceeds campaign threshold (default: 8.0). Email suppressed for 1hr per subject (deduplicates mailing list fan-out) | **Yes** |
| `SenderSpray` | Medium | Single freemail sender emails 500+ unique internal recipients in 24h | No |
| `VictimReply` | **Critical** | Internal user sent a reply to a detected campaign email | **Yes** |
| `VIPTargeted` | **Critical** | Campaign email targeted a configured high-value recipient | **Yes** |
| `DisplayNameReuse` | High | Known display name appeared with an unrecognized, non-internal sender address | No |
| `InternalForwarding` | High | Internal user forwarded a campaign email to colleagues (lateral propagation) | No |
| `ConversationEscalation` | **Critical** | Attacker followed up after victim replied (active conversation detected) | **Yes** |
| `CampaignWave` | High | 3+ unique senders using the same display name within 1 hour (coordinated wave) | No |

### Structured Logging

All detection events are written to `se_campaign.log` with rich metadata for SIEM ingestion:

| Field | Type | Description |
|---|---|---|
| `ts` | time | Detection timestamp |
| `uid` | string | Connection UID |
| `id` | conn_id | Connection 4-tuple |
| `sender` | string | Sender email address |
| `recipients` | string | Recipient addresses (optional) |
| `subject` | string | Email subject line |
| `score` | double | Composite detection score |
| `matched_indicators` | string | Pipe-delimited list of matched indicators |
| `persona` | string | Detected persona name (optional) |
| `is_learned` | bool | Whether detection used a learned (vs static) IOC |
| `is_vip_target` | bool | Whether a VIP recipient was targeted |
| `notice_type` | string | Which notice type triggered this log entry |

### Intel Framework Integration

Confirmed campaign senders (from `CampaignMatch`) are automatically fed into Zeek's Intel framework via `Intel::insert()`. This provides:
- Cross-script visibility of known campaign senders
- Automatic propagation across cluster nodes (handled by the Intel framework)
- Integration with downstream SIEM and threat intelligence platforms

## Installation

### Via zkg

```bash
zkg install SocialEngineering
```

### Manual

```bash
cp -r scripts/ /opt/zeek/share/zeek/site/SocialEngineering/
echo '@load SocialEngineering' >> /opt/zeek/share/zeek/site/local.zeek
zeekctl deploy
```

## Configuration

All options use `&redef` and can be overridden in `local.zeek` without modifying the package.

### Known Sender IOCs

```zeek
# Add newly discovered sender addresses
redef SocialEngineering::known_bad_senders += {
    "newattacker@gmail.com",
};

# Add newly discovered display names
redef SocialEngineering::known_bad_display_names += {
    "New Fake Persona",
};
```

In addition to exact addresses, the package supports regex-based sender matching for campaign naming patterns:

```zeek
# Match disposable Gmail addresses generated by the campaign
redef SocialEngineering::known_bad_sender_patterns += {
    /amyblooms?[0-9]+@gmail\.com/,
    /lilliang?briger\.?[a-z]*[0-9]*@gmail\.com/,
};
```

The package ships with (via `site-config.zeek`):
- `lilliangbriger7886@gmail.com` (confirmed IOC)
- Sender patterns for `amybloom[s]<digits>` and `lillian[g]briger<suffix>` Gmail variants
- Display names: `Amy Bloom`, `Lillian Briger`, `Lillian GBriger`

### Internal Mail Domains

Define which sender domains are considered "your people" for reply detection:

```zeek
redef SocialEngineering::internal_mail_domains += {
    "yourdomain.org",
    "youruniversity.edu",
};
```

Defaults are configured in `site-config.zeek` and can be overridden via `local.zeek`.

### High-Value Targets

Escalate alerting when campaign emails target VIP recipients:

```zeek
redef SocialEngineering::high_value_targets += {
    "director@yourdomain.org",
    "division-head@yourdomain.org",
};
```

When a `CampaignMatch` targets a VIP, the `VIPTargeted` notice fires with `ACTION_EMAIL`.

### Email Alerting

`VictimReply`, `CampaignMatch`, `VIPTargeted`, and `ConversationEscalation` notices trigger `Notice::ACTION_EMAIL` by default. `SenderSpray` is log-only (no email alert).

```zeek
redef SocialEngineering::alert_email_dest = "soc-alerts@yourdomain.org";
```

Zeek's email notification requires `sendmail`. Ensure this is configured:

```zeek
redef Notice::mail_dest = "soc-alerts@yourdomain.org";
redef Notice::sendmail = "/usr/sbin/sendmail";
```

### Scoring Thresholds

```zeek
# Body threshold: fires BodyIndicators notice
# Default 6.0 -- a single persona bio (4.0) + closing phrase (2.5) triggers it
redef SocialEngineering::body_score_threshold = 6.0;

# Campaign threshold: fires CampaignMatch notice + email alert
# Default 8.0 -- requires multiple indicators to match
redef SocialEngineering::campaign_score_threshold = 8.0;
```

### Spray Detection

Spray detection only tracks **freemail senders** (gmail.com, yahoo.com, etc.). Branded-domain senders like newsletters, SaaS notifications, and monitoring systems are excluded to prevent false positives.

```zeek
redef SocialEngineering::spray_threshold = 500.0;  # unique recipients to trigger
redef SocialEngineering::spray_window = 24hr;       # observation window
```

### Campaign Wave Detection

```zeek
redef SocialEngineering::wave_threshold = 3.0;   # unique senders per display name
redef SocialEngineering::wave_window = 1hr;       # observation window
```

Detects when multiple unique sender addresses use the same display name within a time window, indicating an active coordinated campaign wave using disposable addresses.

### Sender Entropy Detection

```zeek
# Freemail domains where high numeric local-part entropy is suspicious
redef SocialEngineering::freemail_domains += { "protonmail.com" };

# Minimum numeric ratio to trigger entropy signal (default: 40%)
redef SocialEngineering::entropy_numeric_ratio = 0.4;
```

### Campaign Tracking Expiry

```zeek
# How long to remember detected campaign emails for reply detection
# Default: 90 days (covers slow-burn social engineering)
redef SocialEngineering::campaign_tracking_expiry = 90 days;
```

## Body Content Indicators

20 weighted indicators extracted from the campaign corpus, organized by category:

| Category | Indicator | Weight | Example |
|---|---|---|---|
| **Persona fingerprint** | Amy Bloom bio | 4.0 | "grew up in Monaco...studied design in Paris" |
| **Persona fingerprint** | Amy Bloom work description | 4.0 | "private art collections...scientific philanthropy" |
| **Persona fingerprint** | Lillian Briger bio | 4.0 | "grew up in Brunei...business administration...Stanford" |
| **Persona fingerprint** | Lillian Briger work description | 4.0 | "advising royal families...education planning" |
| **Persona signature** | Known sign-off | 5.0 | "Warm regards...Amy Bloom" / "Lillian Briger" |
| **Manipulation** | Guilt phrase | 5.0 | "Are you unhappy with what I said" |
| **Manipulation** | Emotional pressure | 5.0 | "didn't sit right with you" |
| **Authority claim** | Royal families | 3.0 | "collaborating with several royal families" |
| **Authority claim** | Family offices | 3.0 | "European and American family offices" |
| **Question template** | Broader question | 3.0 | "very curious to hear your perspective on one broader question" |
| **Question template** | Binary framing | 2.5 | "Will the biggest breakthroughs come from" |
| **Question template** | Transformative advances | 2.0 | "Where do you see the most transformative" |
| **Closing template** | Low-commitment ask | 2.5 | "If you ever have a moment to share" |
| **Closing template** | Flattery close | 2.0 | "I would truly/genuinely value/enjoy hearing" |
| **Closing template** | Scientist flattery | 2.0 | "Conversations with scientists...incredibly insightful" |
| **Infrastructure** | Long-term interest | 1.5 | "long-term scientific/education infrastructure" |
| **Philanthropy** | Support claim | 1.5 | "supporting research, education, and cultural projects" |
| **Flattery** | Template phrase | 1.0 | "It is fascinating/remarkable how" |
| **Flattery** | Research opener | 1.0 | "I recently came across your work" |
| **Location harvesting** | Location question | 3.0 | "what area are you based in" |

### Structural Amplifiers

These signals only fire when at least one body indicator already matched (amplifier gate), preventing false positives:

| Amplifier | Weight | Condition |
|---|---|---|
| Plain text structure | +1.0 | Single MIME entity, no multipart, no HTML, no attachments |
| Sender entropy | +1.0 | Freemail local-part has 40%+ digits (e.g., `amyblooms452354`) |
| No links/attachments | +1.0 | Body contains no URLs and email has no attachments |

Scoring examples against the default thresholds:

- **Typical Amy Bloom email**: scores 36-51 (matches 12-15 indicators including sender pattern + subject)
- **Typical Lillian Briger email**: scores 36-51 (matches 8-10 indicators including sender/IOC + subject)
- **Benign academic email**: scores 0-2 (may match generic flattery at most)

## Automatic IOC Learning (Pivoting)

When a `CampaignMatch` fires (score exceeds `campaign_score_threshold`), the package automatically learns the sender address and subject line as runtime IOCs — **but only for external senders**. Internal users whose replies happen to score above threshold (e.g., via subject pattern matching) are explicitly excluded from learning, preventing cascading false positives on legitimate internal email.

This creates a feedback loop: a confirmed campaign email teaches the system to instantly flag future emails from the same sender or with the same subject -- even if they don't match any static pattern or body indicator.

| Learned IOC | Runtime Set | What It Enables |
|---|---|---|
| Sender address | `learned_bad_senders` | Future emails from this sender immediately fire `KnownSender` (+10.0 score) |
| Subject line (normalized) | `learned_bad_subjects` | Future emails with this subject immediately fire `SubjectMatch` (+3.0 score) |

Both sets expire after `campaign_tracking_expiry` (default: 90 days) and are purely in-memory -- no configuration files are modified. The learning persists across the Zeek process lifetime but resets on restart.

This is particularly useful when the attacker:
- Reuses a sender address that didn't match any static pattern
- Sends a follow-up email with the same subject to a different target
- Changes body content enough to evade body scoring, but keeps the same sender/subject

## Reply Detection

When a campaign email is detected, the package tracks three attributes for future reply matching:

| Tracked Attribute | Storage | What Catches a Reply |
|---|---|---|
| Sender address | `tracked_campaign_senders` | Outbound email TO the campaign sender |
| Message-ID | `tracked_campaign_msg_ids` | `In-Reply-To` header matches original email |
| Normalized subject | `tracked_campaign_subjects` | `Re:` subject to external recipient matches |

All three tables expire after `campaign_tracking_expiry` (default: 90 days).

An outbound email triggers `VictimReply` when it originates from an `internal_mail_domains` address and matches **any one** of the three methods. The notice includes:
- The victim's email address
- The campaign sender they replied to
- The subject line
- Which detection method triggered

## Conversation State Tracking

The package tracks full attacker-victim conversation lifecycles through a three-state machine:

```
CAMPAIGN_SENT  -->  VICTIM_REPLIED  -->  ATTACKER_FOLLOWUP
   (inbound)         (outbound)           (inbound)
```

- **CAMPAIGN_SENT**: Recorded when `CampaignMatch` fires for each sender-recipient pair
- **VICTIM_REPLIED**: Transitions when `VictimReply` detects an outbound reply
- **ATTACKER_FOLLOWUP**: Transitions when the same attacker sends another email to the same victim who replied. Fires `ConversationEscalation` with `ACTION_EMAIL` -- this is the highest-risk state

Additionally, **follow-up escalation** boosts the score by +5.0 when a campaign sender re-contacts the same recipient (even without a prior reply). This catches the guilt/pressure follow-up phase ("Are you unhappy with what I said?").

## Internal Forwarding Detection

When an internal user forwards a campaign email to colleagues (subject starts with "Fwd:" and body content scores above the body threshold), `InternalForwarding` fires. This indicates the phishing email is spreading laterally inside the organization -- a different and operationally significant event from a reply.

Internal senders and branded-domain senders are excluded from the SumStats spray detection feed — only freemail senders are tracked. This eliminates false spray alerts from internal forwarding, newsletters, SaaS notifications, and monitoring systems.

## Display Name Reuse Detection

Detects when a known campaign display name (e.g., "Amy Bloom") appears with a sender address that doesn't match any IOC, pattern, or learned address. This catches the campaign pivoting to completely new naming schemes while keeping the same persona. Only fires for non-internal sender domains.

## Cluster Support

The package is fully cluster-aware. All shared state tables are synchronized across Zeek cluster nodes:

| Component | Cluster Handling |
|---|---|
| `learned_bad_senders`, `learned_bad_subjects` | Worker -> proxy (HRW) -> broadcast to workers |
| `tracked_campaign_senders/msg_ids/subjects` | Worker -> proxy (HRW) -> broadcast to workers |
| `campaign_contact_pairs` | Worker -> proxy (HRW) -> broadcast to workers |
| `conversation_states` | Worker -> proxy (HRW) -> broadcast to workers |
| SumStats (spray, wave) | Handled natively by SumStats framework |
| Intel framework | Handled natively by Intel framework |

Workers perform all detection locally against their own copy of the state tables. When state changes (e.g., new learned IOC, conversation state transition), the update is published to a proxy via `Broker::publish` with `Cluster::hrw_topic` for Rendezvous hashing, the proxy updates its authoritative copy and broadcasts to all workers. This ensures every node has a consistent view without cross-node latency on the detection path.

In standalone mode (non-cluster), the same wrapper functions simply update local state directly.

## Testing

```bash
cd tests && btest -c btest.cfg
```

### Test Traces

The package ships with three anonymized pcap files in `tests/Traces/`:

| File | Contents | Size |
|---|---|---|
| `campaign-samples.pcap` | 10 campaign email flows (5 Amy, 3 Lillian, 2 Lillian with IOC) | 152 KB |
| `campaign-samples-with-reply.pcap` | Same 10 flows + 1 synthetic victim reply flow | 163 KB |
| `conversation.pcap` | Full multi-stage attacker-victim conversation lifecycle (inbound campaign, victim reply, attacker follow-up, internal forwarding) | 168 KB |

All internal addresses are anonymized with length-preserving substitution (TCP reassembly is not affected).

### Test Coverage (25 tests)

| Test | Type | What It Validates |
|---|---|---|
| `body-scoring` | Unit | All 20 indicators loaded, weights correct, patterns match campaign text |
| `campaign-log` | Unit | Structured `se_campaign.log` stream created with correct fields |
| `campaign-wave` | Integration | CampaignWave fires for Amy Bloom (3+ senders) and Lillian GBriger (3+ senders) |
| `cluster-support` | Unit | All 4 cluster wrapper functions update state correctly in standalone mode |
| `conversation-tracking` | Integration | ConversationState enum, states populated as CAMPAIGN_SENT, no false escalation |
| `display-name-reuse` | Integration | DisplayNameReuse suppressed when sender matches IOC patterns |
| `follow-up-escalation` | Integration | Contact pairs recorded, no false FOLLOW_UP_CONTACT on first-contact pcap |
| `intel-integration` | Unit | Intel framework indicators inserted for campaign senders |
| `internal-forwarding` | Integration | InternalForwarding notice type registered, no false triggers on pcap |
| `known-sender-ioc` | Unit | IOC sets loaded with correct addresses and display names |
| `mime-structure` | Unit | MIME fingerprint tracking (entity count, multipart, HTML, attachment) |
| `no-false-positive` | Unit | Benign email body scores below threshold, campaign body scores above |
| `no-internal-learning` | Integration | Internal senders excluded from learned IOCs, tracked senders, contact pairs, and conversation state |
| `no-link-signal` | Unit | No-links/no-attachments amplifier fires correctly |
| `notice-types` | Unit | All 10 notice types registered, configuration defaults correct |
| `pcap-campaign-detection` | Integration | 10 BodyIndicators + 10 CampaignMatch + 10 KnownSender + 2 CampaignWave |
| `pcap-conversation-lifecycle` | Integration | Full conversation lifecycle: CampaignMatch + VictimReply + ConversationEscalation on real multi-stage email exchange |
| `pcap-known-sender-ioc` | Integration | `lilliangbriger7886@gmail.com` detected in live SMTP traffic |
| `pcap-no-false-positives` | Integration | Zero false positives on anonymized internal senders |
| `pcap-score-distribution` | Integration | Both personas detected, scores 37-52.5, all above threshold |
| `pcap-victim-reply` | Integration | VictimReply fires when internal user replies to campaign sender |
| `reply-detection` | Unit | Internal domain config, tracking tables, VictimReply notice type |
| `sender-entropy` | Unit | Local-part numeric ratio calculation for freemail entropy detection |
| `subject-patterns` | Unit | 18 campaign subjects match, 6 legitimate subjects correctly rejected |
| `vip-targets` | Integration | VIPTargeted fires for configured VIP, includes ACTION_EMAIL |

## File Structure

```
scripts/
    __load__.zeek         Module loader
    main.zeek             Types, IOC sets, state tables, helper functions
    logging.zeek          Dedicated se_campaign.log stream
    cluster.zeek          Cluster-aware state synchronization
    detection.zeek        Event handlers for all detection layers
    intel.zeek            Intel framework integration
    site-config.zeek      Site-specific IOCs, patterns, and config

tests/
    btest.cfg             Test framework configuration
    Traces/               Anonymized PCAP test data
    Baseline/             Expected output baselines
    SocialEngineering/    25 test case scripts
```

## Adapting for Other Campaigns

This package is designed around a specific campaign but its architecture is reusable. To adapt for a different social engineering campaign:

1. **Add sender IOCs** to `known_bad_senders`, `known_bad_sender_patterns`, and `known_bad_display_names`
2. **Add subject patterns** to `subject_patterns`
3. **Replace body indicators** in `body_indicators` with phrases from the new campaign
4. **Update internal domains** in `internal_mail_domains`
5. **Configure VIP targets** in `high_value_targets` for escalated alerting
6. **Tune thresholds** -- run against a sample pcap and adjust `body_score_threshold`, `campaign_score_threshold`, `wave_threshold`, and `spray_threshold`
7. **Rely on auto-learning** -- once a `CampaignMatch` fires, the sender and subject are automatically learned for pivoting without any manual IOC updates

All static configuration lives in `site-config.zeek` and is `&redef`-able from `local.zeek` -- no package modification required.

## Requirements

- Zeek 7.0+
- SMTP analyzer enabled (ports 25, 587)
- `sendmail` or equivalent for email alerting (optional -- detection works without it)

## License

BSD 3-Clause. See [LICENSE](LICENSE).
