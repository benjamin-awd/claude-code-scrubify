# Changelog

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
