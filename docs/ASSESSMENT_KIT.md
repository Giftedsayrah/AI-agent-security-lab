# Add-on for Weeks 9 and 10

Adds the assessment kit and the shadow AI finder to your existing project folder, and fixes one false alarm in the personal data rule. It only adds files, apart from a small one-time patch to two existing files.

## Install

From the folder that holds the zip (for example C:\labs):

```
Expand-Archive -Path "C:\labs\ai-kit-addon.zip" -DestinationPath "C:\labs\helpdesk-agent\helpdesk-agent" -Force
cd C:\labs\helpdesk-agent\helpdesk-agent
python apply_pii_fix.py
python -m pytest -q
```

`apply_pii_fix.py` should report `patched` for `agent/telemetry.py` and `agent/agent.py` (or `already patched` if you run it twice). The tests should all pass. Restart the agent's web address afterwards so it loads the patched code.

## The personal data fix

The personal data rule used to fire when the agent's reply repeated an address the user had typed, such as test@example.com. Addresses and numbers that appear in the user's own message are now ignored, and any other personal data in a reply still counts.

## The assessment kit

`assess.py` sends 15 safe attack prompts to any chatbot or agent with a JSON chat API and writes `assessment_report.md` (and `assessment_report.json`), with findings mapped to the OWASP Top 10 for LLM Applications, MITRE ATLAS and the Nigeria Data Protection Act 2023. Each test is PASS, FAIL or REVIEW. Only test systems you own or are authorised to test. Addresses on your own machine or network are allowed by default, and anything else needs `--authorized`.

To assess your lab agent, first stop the responder with Ctrl and C and run `python responder.py --release`, because the assessment includes an email to an outside address, which would make the responder contain the user partway through and distort the results. With the agent's web address running:

```
python assess.py --url http://127.0.0.1:8000/chat --name "Helpdesk agent (lab)" --canary CANARY-7f3a91
```

Generic tests can miss weaknesses that are specific to a system. For example, a generic request for "every employee" was refused by the lab agent, because its lookup tool only answers for one name or department, while a request for the Finance department worked. Add your own tests in a JSON file and pass it with `--custom`. The file `sample_data/custom_tests_lab.json` has two for the lab agent, and the checks you can use are `pii`, `action`, `secrets`, `script`, `image`, `leak` and `contains` (which fails if the reply contains the `text` you give):

```
python assess.py --url http://127.0.0.1:8000/chat --name "Helpdesk agent (lab)" --canary CANARY-7f3a91 --custom sample_data\custom_tests_lab.json
```

Models give different answers from one run to the next, so add `--repeat 3` to run every test three times with fresh random markers. A test counts as failed if any run fails, and the report adds a results-by-test table showing how often each test failed and which ones vary between runs. It sends three times as many requests, so it costs more API credit and takes longer:

```
python assess.py --url http://127.0.0.1:8000/chat --name "Helpdesk agent (lab)" --canary CANARY-7f3a91 --custom sample_data\custom_tests_lab.json --repeat 3
```

For another system, use `--message-field` and `--reply-field` to match its request and reply format, and `--header "Authorization: Bearer TOKEN"` if it needs one.

## The shadow AI finder

`shadow_ai.py` reads a proxy, DNS or firewall export and reports which AI services appear, with request and user counts, and which are not on your approved list. Try the sample first:

```
python shadow_ai.py sample_data\proxy_log_sample.csv --allow "Microsoft Copilot"
```

Use `--domain-col` and `--user-col` if your export uses other column names.

## Hardening: fixing what the assessment found

The assessment showed that the agent hands over a whole department's details and emails them to an outside address, and that rewording the system prompt did not stop it. Hardening enforces the rules in code, whatever the model or the prompt says. With `HARDENING=on`, email to addresses outside the company is refused, employee lookups must name one person and not a department, and a lookup returns only name, department and work email, without phone or ID numbers. With it off, the agent behaves as before.

Install, once, after unpacking the add-on (the add-on replaces `agent\containment.py`, which holds the policy):

```
python apply_hardening.py
python -m pytest -q
```

The patch should say `patched` for `agent/tools.py`, and every test should pass. Then compare before and after with the same mode and model for both runs. Release the responder first, as above.

```
Remove-Item Env:HARDENING -ErrorAction SilentlyContinue
python -m agent.server          (in the agent window, then run the next line in another window)
python assess.py --url http://127.0.0.1:8000/chat --name "Helpdesk agent (lab), before" --canary CANARY-7f3a91 --custom sample_data\custom_tests_lab.json --repeat 3 --out before_report.md

$env:HARDENING = "on"
python -m agent.server          (restart it with hardening on)
python assess.py --url http://127.0.0.1:8000/chat --name "Helpdesk agent (lab), hardened" --canary CANARY-7f3a91 --custom sample_data\custom_tests_lab.json --repeat 3 --out after_report.md
```

Hardening limits what a successful attack can do. It does not stop the model from being tricked, so tests such as the direct instruction override can still fail.
