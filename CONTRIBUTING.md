# Contributing to scam-lens

Thanks for helping people spot scams. Small, focused contributions are welcome.

## Ways to help
- **Report a miss or a false alarm:** open an issue using the *Missed or wrongly flagged message*
  template. **Remove names, phone numbers, account numbers and anything personal first.**
- **Add or improve rules:** edit a pack in `src/scam_lens/packs/` (see below).
- **Add a regional pack** for your country or language.
- **Fix bugs, improve docs, add tests.**

## Development setup
```bash
git clone https://github.com/SQasimHamdani/scam-lens.git
cd scam-lens
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

## How a rule looks
Rules are JSON objects in a pack file:

```json
{
  "id": "prize",
  "title": "Claims you have won something",
  "weight": 2,
  "explanation": "One sentence on why this is a red flag, written for a non-expert.",
  "patterns": ["\\byou(?:'ve| have)? (?:been selected|won)\\b"]
}
```

- `weight`: 1 = weak signal, 2 = strong, 3 = very strong. Be conservative.
- `patterns`: case-insensitive regular expressions (remember to escape backslashes in JSON).
- `skip_if_negated`: set to `true` if the phrase also appears in genuine warnings
  (for example "do **not** share your OTP").
- Keep patterns specific. A rule that fires on ordinary messages does more harm than a missed scam.

## Pull request checklist
- [ ] Add or update tests in `tests/` (include a genuine message that must **not** be flagged).
- [ ] `pytest` passes.
- [ ] No personal data or real phone numbers/accounts in examples.
- [ ] The explanation is plain language and does not overclaim.

Keep PRs small and link the issue they address. Be respectful: see the
[Code of Conduct](CODE_OF_CONDUCT.md).
