//! `message::is_clean` must never call a line clean that the full `Value`
//! path would redact. Checked line by line on the benchmark corpus, which
//! mixes every line shape with occasional fake secrets.

#[path = "../benches/common/mod.rs"]
mod common;

use scrub_history::allowlist::{Allowlist, Blacklist};
use scrub_history::entropy::EntropyConfig;
use scrub_history::message;
use scrub_history::patterns::PatternSet;
use serde_json::Value;

#[test]
fn clean_probe_matches_value_path_on_corpus() {
    let ps = PatternSet::load(true).unwrap();
    let (al, bl) = (Allowlist::empty(), Blacklist::empty());
    for entropy in [
        EntropyConfig::default(),
        EntropyConfig {
            enabled: false,
            ..Default::default()
        },
    ] {
        let (mut clean, mut dirty) = (0, 0);
        let corpus =
            common::transcript(common::P50_BYTES) + &common::turn() + &common::secret_line();
        for line in corpus.lines().filter(|l| !l.trim().is_empty()) {
            let mut value: Value = serde_json::from_str(line).unwrap();
            let full_clean = message::scrub_value(&mut value, &ps, &entropy, &al, &bl).is_empty();
            let probe_clean = message::is_clean(line, &ps, &entropy, &al, &bl);
            assert_eq!(probe_clean, full_clean, "{line}");
            if full_clean { clean += 1 } else { dirty += 1 }
        }
        assert!(
            clean > 100 && dirty > 0,
            "corpus should exercise both: {clean} clean, {dirty} dirty"
        );
    }
}
