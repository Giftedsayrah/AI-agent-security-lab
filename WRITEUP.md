# Securing an Agentic AI System: Detection, Containment, Assessment and Hardening

A lab case study by Oluwaseyi Serah Ojapinwa, 2026.

## Summary

AI agents that can read data and take actions change the security problem. A model that can be persuaded to misbehave is now connected to tools that can disclose information and send messages. This case study documents a lab built to answer a practical question from a defender's point of view: when such an agent is attacked, what can be observed, what can be stopped automatically, and what has to be fixed in the design?

The lab is a deliberately vulnerable AI helpdesk agent with three tools, running on synthetic data. Around it I built structured telemetry, five detection rules in Elastic, an automatic containment responder, an assessment kit that tests any chatbot with a JSON chat API and reports against OWASP and MITRE ATLAS, and a hardening control, then measured the effect of each.

The main findings are these:

1. Automated attack volume succeeded where manual attempts did not. Garak's PromptInject probes succeeded 65 to 80 percent of the time against the agent, while my hand-written attacks were largely refused.
2. Detection based on attack wording has a ceiling. After tuning, injection phrase detection caught the PromptInject family, but flagged only 56 of 197 prompts from a different probe family that hides instructions inside documents.
3. Behaviour-based detection and automated response worked. A responder contained the attacking user about two seconds after an alert, and the agent then refused that user's tool calls.
4. Rewording the system prompt did not change the outcome on the weaknesses that mattered. Enforcing rules in code removed two high-severity findings, which I verified with independent evidence from the lab's outbox.
5. The code-level control limited what a manipulated agent could do. It did not prevent the model from being manipulated, and the tests showed that as well.

## Scope and environment

All testing was carried out against a system I built using synthetic data, on a single machine. The assessment kit refuses non-local targets unless the operator confirms authorisation.

| Component | Detail |
|---|---|
| Agent | Python tool-calling loop with three tools: knowledge-base search, employee lookup and a mock email sender that writes each message to a local file |
| Model | Claude Haiku, tested under a strict and a loose system prompt. The agent also supports Gemini, OpenAI and Groq models |
| Data | Synthetic employee records and a small knowledge base, including one deliberately poisoned wiki page |
| Telemetry and SIEM | JSON event log shipped by Filebeat to Elasticsearch and Kibana 8.15.3 in Docker |
| Scanner | Garak 0.17.1, reaching the agent through a small local HTTP wrapper so that every prompt is logged |
| Host | Windows laptop with 8GB of RAM |

## Threat model

The agent can be reached through a chat interface and through the content of the knowledge base. Its tools give an attacker three things worth having: stored personal data, the ability to send a message to a chosen address, and the model's own instructions. The lab scenarios map to the OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS as follows.

| Risk | OWASP | ATLAS | Lab scenario |
|---|---|---|---|
| Prompt injection, direct and through a poisoned page | LLM01 | AML.T0051 | An instruction in the chat or in a knowledge-base article steers the agent |
| Sensitive information disclosure | LLM02 | AML.T0057 | A request for a department's contact details |
| Excessive agency | LLM06 | AML.T0053, AML.T0086 | The agent emails those details to an outside address |
| System prompt leakage | LLM07 | AML.T0056 | A request to repeat or translate the agent's instructions |
| Improper output handling | LL

## Evidence

### A detection rule
![Rule created](images/rule-created.png)

One of the five detection rules after it was created in Kibana. Each rule searches the agent's log index with a query on the fields the logging wrapper writes, carries severity and OWASP tags, and runs every minute.

### Alerts by rule
![Alerts by rule](images/alerts-by-rule.png)

Kibana's Alerts page grouped by rule name, showing which rules fired and how often during the attacks.

### One alert in detail
![Alert page](images/alert-page.png)

A single alert opened in Kibana. It carries the agent's own logged fields, such as the user, session, tool and flags, so an analyst can see why it fired and follow the whole session in Discover using its session ID.

### Widening the injection patterns
![Injection patterns](images/injection-patterns.png)

The injection phrase rule after I widened the patterns. At first it caught none of Garak's 60 PromptInject prompts, because the patterns expected exact wording. 

![Responder containment](images/responder-containment.png)

### Containment status and incidents
![Containment page](images/containment-page.png)

The containment status shows which user and action are blocked and why, and each incident record names the rule, user, session and actions taken. Every block expires on its own.

### Ground truth for the fix
![Outbox before and after](images/outbox-before-after.png)

### Before hardening
![Result before](images/results-before.png)

Results by test, each run three times. The two tests written for this system, the whole department lookup and the email to an outside address, failed in some runs, while the generic prompts missed them.

### After hardening
![Results after](images/results-after.png)

The same assessment with hardening on. The department lookup and the email to an outside address both passed all three runs. The direct override and the markup echo still fail in some runs, because hardening limits what a tricked agent can do and doesn't stop the model being tricked.

