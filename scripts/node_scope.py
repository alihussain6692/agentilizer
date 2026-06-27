"""
node_scope.py — Node scope classification for EDE stratification  (Task 3)

Classifies each n8n node type into one of five scopes:
  egress   — sends data to an external third-party service
  internal — transforms or routes data locally within the workflow engine
  trigger  — entry-point nodes (start the workflow, never transmit outbound)
  ai       — LLM / AI model provider nodes (egress to a model provider)
  unknown  — cannot be classified

Why scopes matter for the paper:
  Top-10 EDE nodes in the raw dataset are utility/trigger nodes (cron, executeWorkflow,
  dataTable, executionData) with 100% EDE because they have no required fields at all.
  These must not appear in GDPR denominators (Article 5(1)(c) only applies to
  processing that involves external transmission of personal data).

  Phase 4 reports three strata:
    (a) Full dataset — all matched nodes (upper bound)
    (b) Clean dataset — excludes inflation/infrastructure nodes (existing Tier 2)
    (c) Egress-only — only egress + ai nodes (headline GDPR-relevant population)

API
---
  classify_scope(node_type: str) -> str     # 'egress' | 'internal' | 'trigger' | 'ai' | 'unknown'
  EGRESS_NODES                              # frozenset of fully-qualified egress node types
  INTERNAL_NODES                            # frozenset of internal node types
  TRIGGER_NODES                             # frozenset of trigger node types
  AI_NODES                                  # frozenset of AI node types
"""

from __future__ import annotations

# ── Trigger nodes (entry points — start a workflow run) ────────────────────────
TRIGGER_NODES: frozenset[str] = frozenset({
    "n8n-nodes-base.manualTrigger",
    "n8n-nodes-base.start",
    "n8n-nodes-base.scheduleTrigger",
    "n8n-nodes-base.cronTrigger",
    "n8n-nodes-base.cron",
    "n8n-nodes-base.webhook",
    "n8n-nodes-base.formTrigger",
    "n8n-nodes-base.emailTrigger",
    "n8n-nodes-base.chatTrigger",
    "n8n-nodes-base.executeWorkflowTrigger",
    "n8n-nodes-base.errorTrigger",
    "n8n-nodes-base.localFileTrigger",
    "n8n-nodes-base.sshTrigger",
    "@n8n/n8n-nodes-langchain.chatTrigger",
    # Service-specific triggers
    "n8n-nodes-base.githubTrigger",
    "n8n-nodes-base.gitlabTrigger",
    "n8n-nodes-base.jiraTrigger",
    "n8n-nodes-base.slackTrigger",
    "n8n-nodes-base.telegramTrigger",
    "n8n-nodes-base.hubspotTrigger",
    "n8n-nodes-base.googleSheetsTrigger",
    "n8n-nodes-base.gmailTrigger",
    "n8n-nodes-base.mailchimpTrigger",
    "n8n-nodes-base.notionTrigger",
    "n8n-nodes-base.asanaTrigger",
    "n8n-nodes-base.trelloTrigger",
    "n8n-nodes-base.stripeWebhook",
    "n8n-nodes-base.stripeTrigger",
    "n8n-nodes-base.typeformTrigger",
    "n8n-nodes-base.freshdesk Trigger",
    "n8n-nodes-base.zendesktrigger",
    "n8n-nodes-base.pipedriveWebhook",
    "n8n-nodes-base.salesforceTrigger",
    "n8n-nodes-base.woocommerceTrigger",
    "n8n-nodes-base.shopifyTrigger",
})

# ── Internal nodes (transform/route locally — no external data transmission) ──
INTERNAL_NODES: frozenset[str] = frozenset({
    # Control flow
    "n8n-nodes-base.if",
    "n8n-nodes-base.switch",
    "n8n-nodes-base.filter",
    "n8n-nodes-base.merge",
    "n8n-nodes-base.splitOut",
    "n8n-nodes-base.splitInBatches",
    "n8n-nodes-base.loop",
    "n8n-nodes-base.wait",
    "n8n-nodes-base.noOp",
    "n8n-nodes-base.stop",
    # Data transformation
    "n8n-nodes-base.set",
    "n8n-nodes-base.code",
    "n8n-nodes-base.function",
    "n8n-nodes-base.functionItem",
    "n8n-nodes-base.aggregate",
    "n8n-nodes-base.summarize",
    "n8n-nodes-base.sort",
    "n8n-nodes-base.limit",
    "n8n-nodes-base.removeDuplicates",
    "n8n-nodes-base.renameKeys",
    "n8n-nodes-base.dateTime",
    "n8n-nodes-base.crypto",
    "n8n-nodes-base.itemLists",
    "n8n-nodes-base.compareDatasets",
    "n8n-nodes-base.convertToFile",
    "n8n-nodes-base.extractFromFile",
    "n8n-nodes-base.spreadsheetFile",
    "n8n-nodes-base.xml",
    "n8n-nodes-base.html",
    "n8n-nodes-base.htmlExtract",
    "n8n-nodes-base.markdown",
    "n8n-nodes-base.moveBinaryData",
    "n8n-nodes-base.readBinaryFile",
    "n8n-nodes-base.readBinaryFiles",
    "n8n-nodes-base.writeBinaryFile",
    "n8n-nodes-base.readPdf",
    "n8n-nodes-base.aiTransform",
    # Utility / annotation
    "n8n-nodes-base.stickyNote",
    "n8n-nodes-base.executeWorkflow",
    "n8n-nodes-base.executionData",
    "n8n-nodes-base.dataTable",
    "n8n-nodes-base.dataStore",
    "n8n-nodes-base.respond",
    "n8n-nodes-base.respondToWebhook",
    "n8n-nodes-base.debugHelper",
    # LangChain utility
    "@n8n/n8n-nodes-langchain.code",
    "@n8n/n8n-nodes-langchain.chainSummarization",
    "@n8n/n8n-nodes-langchain.informationExtractor",
    "@n8n/n8n-nodes-langchain.textClassifier",
    "@n8n/n8n-nodes-langchain.sentimentAnalysis",
    "@n8n/n8n-nodes-langchain.outputParserStructured",
    "@n8n/n8n-nodes-langchain.outputParserAutoFix",
    "@n8n/n8n-nodes-langchain.outputParserItemList",
    "@n8n/n8n-nodes-langchain.memoryBufferWindow",
    "@n8n/n8n-nodes-langchain.memoryPostgres",
    "@n8n/n8n-nodes-langchain.memoryRedisChat",
    "@n8n/n8n-nodes-langchain.memoryVectorStore",
    "@n8n/n8n-nodes-langchain.documentDefaultDataLoader",
    "@n8n/n8n-nodes-langchain.documentBinaryInputLoader",
    "@n8n/n8n-nodes-langchain.embeddingsOpenAi",
    "@n8n/n8n-nodes-langchain.embeddingsCohere",
    "@n8n/n8n-nodes-langchain.textSplitterRecursiveCharacterTextSplitter",
    "@n8n/n8n-nodes-langchain.vectorStoreInMemory",
    "@n8n/n8n-nodes-langchain.toolWorkflow",
    "@n8n/n8n-nodes-langchain.toolCode",
    "@n8n/n8n-nodes-langchain.toolCalculator",
    "@n8n/n8n-nodes-langchain.toolWikipedia",
    "@n8n/n8n-nodes-langchain.toolHttpRequest",
})

# ── AI nodes (send data to external LLM/AI model provider) ───────────────────
AI_NODES: frozenset[str] = frozenset({
    "@n8n/n8n-nodes-langchain.openAi",
    "@n8n/n8n-nodes-langchain.lmOpenAi",
    "@n8n/n8n-nodes-langchain.lmOpenAiChat",
    "@n8n/n8n-nodes-langchain.lmAnthropicClaude",
    "@n8n/n8n-nodes-langchain.lmOllama",
    "@n8n/n8n-nodes-langchain.lmGroq",
    "@n8n/n8n-nodes-langchain.lmMistralCloud",
    "@n8n/n8n-nodes-langchain.lmCohere",
    "@n8n/n8n-nodes-langchain.lmAzureOpenAi",
    "@n8n/n8n-nodes-langchain.lmGoogleVertex",
    "@n8n/n8n-nodes-langchain.lmGooglePalm",
    "@n8n/n8n-nodes-langchain.agent",
    "@n8n/n8n-nodes-langchain.chainLlm",
    "@n8n/n8n-nodes-langchain.chainRetrievalQa",
    "@n8n/n8n-nodes-langchain.chainConversational",
    "@n8n/n8n-nodes-langchain.vectorStoreQA",
    "@n8n/n8n-nodes-langchain.vectorStorePinecone",
    "@n8n/n8n-nodes-langchain.vectorStoreChroma",
    "@n8n/n8n-nodes-langchain.vectorStoreSupabase",
    "@n8n/n8n-nodes-langchain.vectorStoreWeaviate",
    "@n8n/n8n-nodes-langchain.vectorStoreZep",
    "n8n-nodes-base.openAi",
})

# ── Egress nodes (send data to external third-party services) ─────────────────
# These are the headline GDPR-relevant population for Article 5(1)(c) analysis.
EGRESS_NODES: frozenset[str] = frozenset({
    # Email
    "n8n-nodes-base.gmail",
    "n8n-nodes-base.microsoftOutlook",
    "n8n-nodes-base.emailSend",
    "n8n-nodes-base.emailReadImap",
    "n8n-nodes-base.sendEmail",
    "n8n-nodes-base.mailchimp",
    "n8n-nodes-base.sendGrid",
    "n8n-nodes-base.mailjet",
    "n8n-nodes-base.mandrill",
    "n8n-nodes-base.postmark",
    "n8n-nodes-base.sparkPost",
    "n8n-nodes-base.sendInBlue",
    "n8n-nodes-base.elasticEmail",
    # Communication / Messaging
    "n8n-nodes-base.slack",
    "n8n-nodes-base.telegram",
    "n8n-nodes-base.discord",
    "n8n-nodes-base.mattermost",
    "n8n-nodes-base.twilio",
    "n8n-nodes-base.vonage",
    "n8n-nodes-base.messagebird",
    "n8n-nodes-base.plivo",
    "n8n-nodes-base.whatsApp",
    "n8n-nodes-base.teams",
    "n8n-nodes-base.microsoftTeams",
    "n8n-nodes-base.zoom",
    "n8n-nodes-base.intercom",
    "n8n-nodes-base.crisp",
    "n8n-nodes-base.drift",
    "n8n-nodes-base.freshdesk",
    "n8n-nodes-base.zendesk",
    "n8n-nodes-base.helpScout",
    "n8n-nodes-base.livechat",
    # CRM
    "n8n-nodes-base.hubspot",
    "n8n-nodes-base.salesforce",
    "n8n-nodes-base.pipedrive",
    "n8n-nodes-base.zohocrm",
    "n8n-nodes-base.copper",
    "n8n-nodes-base.activeCampaign",
    "n8n-nodes-base.vbout",
    "n8n-nodes-base.sugarcrm",
    "n8n-nodes-base.monday",
    "n8n-nodes-base.clickup",
    # Storage / Documents
    "n8n-nodes-base.googleDrive",
    "n8n-nodes-base.dropbox",
    "n8n-nodes-base.box",
    "n8n-nodes-base.oneDrive",
    "n8n-nodes-base.googleSheets",
    "n8n-nodes-base.airtable",
    "n8n-nodes-base.notion",
    "n8n-nodes-base.coda",
    "n8n-nodes-base.googleDocs",
    "n8n-nodes-base.microsoftWord",
    "n8n-nodes-base.microsoftExcel",
    "n8n-nodes-base.s3",
    "n8n-nodes-base.awsS3",
    "n8n-nodes-base.googleCloudStorage",
    # Developer / Project management
    "n8n-nodes-base.github",
    "n8n-nodes-base.gitlab",
    "n8n-nodes-base.jira",
    "n8n-nodes-base.asana",
    "n8n-nodes-base.trello",
    "n8n-nodes-base.linear",
    "n8n-nodes-base.basecamp",
    "n8n-nodes-base.todoist",
    "n8n-nodes-base.harvest",
    "n8n-nodes-base.clockify",
    "n8n-nodes-base.toggl",
    # E-commerce / Payments
    "n8n-nodes-base.shopify",
    "n8n-nodes-base.woocommerce",
    "n8n-nodes-base.stripe",
    "n8n-nodes-base.paypal",
    "n8n-nodes-base.chargebee",
    "n8n-nodes-base.quickbooks",
    "n8n-nodes-base.xero",
    "n8n-nodes-base.freshbooks",
    # Marketing / Analytics
    "n8n-nodes-base.googleAnalytics",
    "n8n-nodes-base.mixpanel",
    "n8n-nodes-base.segment",
    "n8n-nodes-base.amplitude",
    "n8n-nodes-base.customerIo",
    "n8n-nodes-base.klaviyo",
    "n8n-nodes-base.convertkit",
    # Social
    "n8n-nodes-base.twitter",
    "n8n-nodes-base.facebook",
    "n8n-nodes-base.instagram",
    "n8n-nodes-base.linkedIn",
    # Generic HTTP (treated as egress — external call)
    "n8n-nodes-base.httpRequest",
    # Database (external)
    "n8n-nodes-base.postgres",
    "n8n-nodes-base.mysql",
    "n8n-nodes-base.mongodb",
    "n8n-nodes-base.redis",
    "n8n-nodes-base.microsoftSql",
    "n8n-nodes-base.mariadb",
    "n8n-nodes-base.cockroachDb",
    "n8n-nodes-base.snowflake",
    "n8n-nodes-base.bigQuery",
    "n8n-nodes-base.dynamoDb",
    # Misc
    "n8n-nodes-base.caldav",
    "n8n-nodes-base.googleCalendar",
    "n8n-nodes-base.iCalendar",
    "n8n-nodes-base.microsoftCalendar",
    "n8n-nodes-base.noCrm",
    "n8n-nodes-base.supabase",
    "n8n-nodes-base.pagerDuty",
    "n8n-nodes-base.opsgenie",
    "n8n-nodes-base.uptimeRobot",
})


def classify_scope(node_type: str) -> str:
    """
    Classify a node type string into one of: egress | internal | trigger | ai | unknown.

    Matching order (first match wins):
      1. Explicit AI_NODES membership → 'ai'
      2. Explicit TRIGGER_NODES membership → 'trigger'
      3. Explicit INTERNAL_NODES membership → 'internal'
      4. Explicit EGRESS_NODES membership → 'egress'
      5. Short-name heuristics for LangChain nodes not explicitly listed
      6. 'unknown'
    """
    nt = node_type.strip()

    if nt in AI_NODES:
        return "ai"
    if nt in TRIGGER_NODES:
        return "trigger"
    if nt in INTERNAL_NODES:
        return "internal"
    if nt in EGRESS_NODES:
        return "egress"

    # Heuristic: @n8n/n8n-nodes-langchain.* — classify by short name pattern
    short = nt.rsplit(".", 1)[-1].lower() if "." in nt else nt.lower()

    if nt.startswith("@n8n/n8n-nodes-langchain"):
        if short.startswith("lm") or short.startswith("agent") or "chain" in short:
            return "ai"
        if "trigger" in short:
            return "trigger"
        return "internal"   # other langchain nodes are memory/tools/splitters

    if short.endswith("trigger"):
        return "trigger"

    # Nodes with 'httpRequest' in name but not already classified
    if "httprequest" in short:
        return "egress"

    return "unknown"
