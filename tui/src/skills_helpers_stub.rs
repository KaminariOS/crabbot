use codex_core::skills::model::SkillMetadata;
use codex_utils_fuzzy_match::fuzzy_match;

use crate::text_formatting::truncate_text;

pub(crate) const SKILL_NAME_TRUNCATE_LEN: usize = 21;

pub(crate) fn truncate_skill_name(name: &str) -> String {
    truncate_text(name, SKILL_NAME_TRUNCATE_LEN)
}

pub(crate) fn match_skill(
    filter: &str,
    display_name: &str,
    skill_name: &str,
) -> Option<(Option<Vec<usize>>, i32)> {
    if let Some((indices, score)) = fuzzy_match(display_name, filter) {
        return Some((Some(indices), score));
    }
    if display_name != skill_name
        && let Some((_indices, score)) = fuzzy_match(skill_name, filter)
    {
        return Some((None, score));
    }
    None
}

#[allow(dead_code)]
pub(crate) fn skill_display_name(skill: &SkillMetadata) -> &str {
    skill.name.as_str()
}

#[allow(dead_code)]
pub(crate) fn skill_description(skill: &SkillMetadata) -> &str {
    skill.description.as_str()
}
