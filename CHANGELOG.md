# Changelog

## [0.4.0](https://github.com/benjamin-awd/claude-code-scrubify/compare/scrub-history-v0.3.0...scrub-history-v0.4.0) (2026-03-15)


### Features

* add configurable min_string_length for blacklist entries ([3c0b3e6](https://github.com/benjamin-awd/claude-code-scrubify/commit/3c0b3e6523122b401caebc5fa3faa0aab88bcb01))
* add Recent Redactions section to status and reorder layout ([75994b7](https://github.com/benjamin-awd/claude-code-scrubify/commit/75994b7a1e33dae1edf3e9ea7ce05c335ceea1bb))
* scrub subagent transcripts in stop hook ([3454c4c](https://github.com/benjamin-awd/claude-code-scrubify/commit/3454c4cc14b697da0c17123481afade06fcdfa17))


### Bug Fixes

* correct subagent discovery path in stop hook ([3534bf4](https://github.com/benjamin-awd/claude-code-scrubify/commit/3534bf42e4138b738d1c151e47ea742bfdf1b36a))
* scrub all strings in progress message data field ([c8f3e8c](https://github.com/benjamin-awd/claude-code-scrubify/commit/c8f3e8c5a8e826af438f1cbc7db5363412ed2d52))
* scrub toolUseResult in user messages ([af09734](https://github.com/benjamin-awd/claude-code-scrubify/commit/af097342108ce3ac848fd781a095fe5c691afb7e))

## [0.3.0](https://github.com/benjamin-awd/claude-code-scrubify/compare/scrub-history-v0.2.0...scrub-history-v0.3.0) (2026-03-12)


### Features

* add blacklist feature for always-redacting configured strings ([6370dfe](https://github.com/benjamin-awd/claude-code-scrubify/commit/6370dfe5b83ea893fb326d4926a3d94296aca380))
* add hash-based blacklist for exact-match redaction without plaintext ([a9cab6a](https://github.com/benjamin-awd/claude-code-scrubify/commit/a9cab6ac43fe631cb0203e745d412a077e4f37b8))
* add indicatif progress bar to scan command ([906c883](https://github.com/benjamin-awd/claude-code-scrubify/commit/906c8836357f870b7dff3333be10c5a1617e1247))
* add mtime-based scan cache to skip unchanged files ([33fafaa](https://github.com/benjamin-awd/claude-code-scrubify/commit/33fafaacd57f8cc1b4794d90a23163289a7525ea))
* add sparkline visualizations for latency and redactions in status ([d8f5330](https://github.com/benjamin-awd/claude-code-scrubify/commit/d8f5330668485671bbd2f55e8882ee21bbfc4b85))
* show version in status command header ([c64a948](https://github.com/benjamin-awd/claude-code-scrubify/commit/c64a948a486fa1cd92e2f4a7dd36111ff17c3781))


### Bug Fixes

* speed up status command and shorten file path display ([5b23b00](https://github.com/benjamin-awd/claude-code-scrubify/commit/5b23b00100bfcf73f927788892aaad7993bf2104))

## [0.2.0](https://github.com/benjamin-awd/claude-code-scrubify/compare/scrub-history-v0.1.0...scrub-history-v0.2.0) (2026-03-12)


### Features

* add `scrub-history init` interactive setup wizard ([e9b01f8](https://github.com/benjamin-awd/claude-code-scrubify/commit/e9b01f88cb77e0d19fa7dbf2eb6c601f9a5e1b6c))
* add `scrub-history status` command with persistent run stats ([8f16d07](https://github.com/benjamin-awd/claude-code-scrubify/commit/8f16d07085ce1559b383fde102a5bb5117b875f5))
* add allowlist via [allowlist] section in ~/.claude/scrubber.toml ([4f72784](https://github.com/benjamin-awd/claude-code-scrubify/commit/4f72784f9a6f2d253a641347763fdced003edd67))
* add async hook option to `scrub-history init` wizard ([7f74e03](https://github.com/benjamin-awd/claude-code-scrubify/commit/7f74e036d6f5ddb28b46e9085757d0abaff9e9cd))
* add criterion benchmark suite for JSONL scrubbing performance ([34468e5](https://github.com/benjamin-awd/claude-code-scrubify/commit/34468e5fa533124fe628203aae53815c5045f415))
* add hook latency tracking with percentile stats ([a5745e2](https://github.com/benjamin-awd/claude-code-scrubify/commit/a5745e252a5c1b44a46417b34c08cf869eaebf26))
* add key-value pair awareness for sensitive field names ([0e5f988](https://github.com/benjamin-awd/claude-code-scrubify/commit/0e5f98835e726bf5092fb44646e98b51cde778dd))
* add keyword pre-filtering per pattern ([b60666b](https://github.com/benjamin-awd/claude-code-scrubify/commit/b60666bbb3f49e7b2451c647de01d267b443e5b3))
* add minimum value length threshold for redaction ([9fbb371](https://github.com/benjamin-awd/claude-code-scrubify/commit/9fbb371e70b2f1a5452d481eeadc566bf214663c))
* add rustfmt import grouping and entropy exclusion config support ([c17d865](https://github.com/benjamin-awd/claude-code-scrubify/commit/c17d865a05d8c6c5a9658f0ec73e4a9d9afdf616))
* add secretGroup capture groups for targeted redaction ([9055b97](https://github.com/benjamin-awd/claude-code-scrubify/commit/9055b979e02e885c1032732b5404ff80da931d4a))
* add user-configurable entropy exclusions, truncate secrets in hook logs, and enable ANSI colors ([c096059](https://github.com/benjamin-awd/claude-code-scrubify/commit/c096059a9f9ef05c44edf6afdfa1fbd06534ab52))
* initial commit ([2b8e320](https://github.com/benjamin-awd/claude-code-scrubify/commit/2b8e320e35ca39ad4fa491a4da799cd5b4c04886))
* log per-redaction details at debug level in hook ([006ed4b](https://github.com/benjamin-awd/claude-code-scrubify/commit/006ed4bbe6de539ed36ccd86c20baa85d9b61bee))


### Bug Fixes

* deduplicate same secret appearing in multiple JSON fields per line ([2c9307e](https://github.com/benjamin-awd/claude-code-scrubify/commit/2c9307e2e940e32e8fddd48e73a312978470a3e1))
* grant release-please workflow write permissions for branches and PRs ([1d1c6e0](https://github.com/benjamin-awd/claude-code-scrubify/commit/1d1c6e077d9b0a109277aec1f97dc2ee955b2a1a))
* skip already-redacted placeholders in secret_group patterns ([23e5e4d](https://github.com/benjamin-awd/claude-code-scrubify/commit/23e5e4d4de2db9a6cd215c32d3ef4a4093ddf104))


### Performance Improvements

* avoid allocation in is_sensitive_key by using ends_with + byte check ([eba8334](https://github.com/benjamin-awd/claude-code-scrubify/commit/eba833478fdc9b8c29346f086b3c478d7574767e))
* lowercase text once for keyword checks instead of per-pattern ([c1dc9c1](https://github.com/benjamin-awd/claude-code-scrubify/commit/c1dc9c18be28cc0080132ca7bd1bc82562ec4bcd))
