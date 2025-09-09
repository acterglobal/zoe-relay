use whatsmeow::MessageEvent;

/// Check if a message should be displayed based on filters
pub fn should_display_message(
    message: &MessageEvent,
    filter_sender: &Option<String>,
    filter_chat: &Option<String>,
    groups_only: bool,
    dm_only: bool,
) -> bool {
    // Check sender filter
    if let Some(sender_filter) = filter_sender
        && !message
            .sender
            .to_lowercase()
            .contains(&sender_filter.to_lowercase())
    {
        return false;
    }

    // Check chat filter
    if let Some(chat_filter) = filter_chat
        && !message
            .chat
            .to_lowercase()
            .contains(&chat_filter.to_lowercase())
    {
        return false;
    }

    // Check group/DM filters
    let is_group = message.chat.contains("-") && message.chat.contains("@g.us");

    if groups_only && !is_group {
        return false;
    }

    if dm_only && is_group {
        return false;
    }

    true
}

/// Extract a readable name from a WhatsApp JID
pub fn extract_name_from_jid(jid: &str) -> String {
    // Extract the part before @ and format it nicely
    let name_part = jid.split('@').next().unwrap_or(jid);

    // For group JIDs, extract the readable part
    if name_part.contains('-') {
        let parts: Vec<&str> = name_part.split('-').collect();
        if parts.len() >= 2 {
            // Group JIDs often have format: timestamp-groupid
            return format!("Group-{}", &parts[1][..8.min(parts[1].len())]);
        }
    }

    // For regular JIDs, just use the phone number part
    if name_part.len() >= 10 {
        format!("+{}", name_part)
    } else {
        name_part.to_string()
    }
}
