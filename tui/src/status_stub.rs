pub(crate) fn format_tokens_compact(value: i64) -> String {
    const K: i64 = 1_000;
    const M: i64 = 1_000_000;
    const B: i64 = 1_000_000_000;

    let abs = value.abs();
    if abs >= B {
        format!("{:.1}B", value as f64 / B as f64)
    } else if abs >= M {
        format!("{:.1}M", value as f64 / M as f64)
    } else if abs >= K {
        format!("{:.1}k", value as f64 / K as f64)
    } else {
        value.to_string()
    }
}
