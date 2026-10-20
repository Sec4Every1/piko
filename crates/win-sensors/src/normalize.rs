use piko_event_schema::{EventRecord, EventTarget, RawEvidence, SecurityEvent, Severity};
use quick_xml::{events::Event, Reader, XmlVersion};
use std::{error::Error, io};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub struct EventMetadata {
    pub provider: String,
    pub channel: String,
    pub event_id: u32,
    pub record_id: u64,
    pub unix_ms: i64,
    pub level: u8,
}
impl EventMetadata {
    pub fn parse(xml: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        if xml.len() > 192 * 1024 {
            return Err("XML exceeds sensor limit".into());
        }
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);
        let mut path: Vec<String> = Vec::new();
        let (mut provider, mut channel, mut timestamp) = (None, None, None);
        let (mut event_id, mut record_id, mut level) = (None, None, None);
        let mut root = false;
        loop {
            let item = reader.read_event()?;
            let is_start = matches!(&item, Event::Start(_));
            match item {
                Event::Start(ref tag) | Event::Empty(ref tag) => {
                    let name = tag.local_name().as_ref().to_owned();
                    if path.len() > 32 {
                        return Err("XML nesting limit".into());
                    }
                    if path.is_empty() {
                        if root || name != "Event" {
                            return Err("expected single Event root".into());
                        }
                        root = true;
                    }
                    if path == ["Event".to_owned(), "System".to_owned()] {
                        for attr in tag.attributes() {
                            let attr = attr?;
                            if name == "Provider" && attr.key.as_ref() == "Name" {
                                let value =
                                    attr.normalized_value(XmlVersion::Implicit1_0)?.into_owned();
                                if provider.replace(value).is_some() {
                                    return Err("duplicate provider".into());
                                }
                            }
                            if name == "TimeCreated" && attr.key.as_ref() == "SystemTime" {
                                let value =
                                    attr.normalized_value(XmlVersion::Implicit1_0)?.into_owned();
                                if timestamp.replace(value).is_some() {
                                    return Err("duplicate timestamp".into());
                                }
                            }
                        }
                    }
                    if is_start {
                        path.push(name);
                    }
                }
                Event::End(_) => {
                    path.pop();
                }
                Event::Text(text) => {
                    if path.len() == 3 && path[0] == "Event" && path[1] == "System" {
                        let value = text.xml_content(XmlVersion::Implicit1_0);
                        match path[2].as_str() {
                            "Channel" => {
                                if channel.replace(value.into_owned()).is_some() {
                                    return Err("duplicate channel".into());
                                }
                            }
                            "EventID" => {
                                if event_id.replace(value.parse::<u32>()?).is_some() {
                                    return Err("duplicate EventID".into());
                                }
                            }
                            "EventRecordID" => {
                                if record_id.replace(value.parse::<u64>()?).is_some() {
                                    return Err("duplicate record ID".into());
                                }
                            }
                            "Level" => {
                                if level.replace(value.parse::<u8>()?).is_some() {
                                    return Err("duplicate level".into());
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Event::DocType(_) => return Err("DTD is not accepted".into()),
                Event::GeneralRef(reference) => {
                    let value = reference.xml_content(XmlVersion::Implicit1_0);
                    if !["lt", "gt", "amp", "quot", "apos"].contains(&value.as_ref())
                        && !value.starts_with('#')
                    {
                        return Err("custom entity is not accepted".into());
                    }
                }
                Event::Eof => break,
                _ => {}
            }
        }
        if !path.is_empty() {
            return Err("incomplete XML".into());
        }
        let provider = provider.ok_or("missing provider")?;
        if provider.is_empty() || provider.len() > 256 {
            return Err("provider size".into());
        }
        let unix_ms = i64::try_from(
            OffsetDateTime::parse(&timestamp.ok_or("missing time")?, &Rfc3339)?
                .unix_timestamp_nanos()
                / 1_000_000,
        )?;
        if unix_ms < 0 {
            return Err("invalid time".into());
        }
        Ok(Self {
            provider,
            channel: channel.ok_or("missing channel")?,
            event_id: event_id.ok_or("missing event ID")?,
            record_id: record_id.filter(|id| *id > 0).ok_or("missing record ID")?,
            unix_ms,
            level: level.ok_or("missing level")?,
        })
    }
}

pub fn normalize(
    xml: String,
    channel: &str,
    bookmark: String,
    mut event: SecurityEvent,
) -> io::Result<EventRecord> {
    let metadata = EventMetadata::parse(&xml).map_err(io::Error::other)?;
    if metadata.channel != channel || bookmark.len() > 8192 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source/channel/bookmark mismatch",
        ));
    }
    event.sensor_id = format!("windows.event_log.{channel}");
    event.event_category = "windows_event_log".into();
    event.event_type = format!("windows.event_log.{}", metadata.event_id);
    event.wall_clock_time = metadata.unix_ms;
    // Windows source level describes operational importance, not maliciousness.
    event.severity = match metadata.level {
        1 => Severity::Critical,
        2 => Severity::High,
        3 => Severity::Medium,
        _ => Severity::Info,
    };
    event.actor_identity = None;
    event.process = None;
    event.parent_process = None;
    event.logon_session = None;
    event.target = Some(EventTarget {
        kind: "windows_event_record".into(),
        identifier: format!(
            "{}:{}:{}",
            metadata.channel, metadata.provider, metadata.record_id
        ),
    });
    event.operation = "observe".into();
    event.result = "recorded_by_windows".into();
    event.integrity_metadata.source_integrity = Some(bookmark);
    let evidence_id = Uuid::new_v4();
    event.raw_evidence_reference = Some(evidence_id);
    let raw = RawEvidence {
        evidence_id,
        source: event.sensor_id.clone(),
        content_type: "application/xml; charset=utf-8".into(),
        observed_at_unix_ms: event.observation_time,
        bytes: xml.into_bytes(),
    };
    event.validate().map_err(io::Error::other)?;
    Ok(EventRecord {
        event,
        raw_evidence: Some(raw),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const XML: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager"/><EventID Qualifiers="16384">7036</EventID><Level>4</Level><TimeCreated SystemTime="2026-10-04T10:20:30.1234567Z"/><EventRecordID>42</EventRecordID><Execution ProcessID="888" ThreadID="44"/><Channel>System</Channel></System><EventData><Data Name="param1">A service</Data></EventData></Event>"#;
    #[test]
    fn normalizes_real_windows_shape_without_fabricated_actor() -> io::Result<()> {
        let seed =
            SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 1_900_000_000_000, 123);
        let record = normalize(XML.into(), "System", "<BookmarkList/>".into(), seed)?;
        assert_eq!(record.event.event_type, "windows.event_log.7036");
        assert!(record.event.process.is_none());
        assert!(record.event.actor_identity.is_none());
        assert_eq!(record.event.wall_clock_time, 1_791_109_230_123);
        assert_eq!(
            record.raw_evidence.map(|e| e.bytes),
            Some(XML.as_bytes().to_vec())
        );
        Ok(())
    }
    #[test]
    fn rejects_truncation_duplicates_dtd_and_channel_spoofing() {
        assert!(EventMetadata::parse(&XML[..XML.len() - 8]).is_err());
        assert!(EventMetadata::parse(&XML.replace(
            "<EventID Qualifiers=\"16384\">7036</EventID>",
            "<EventID>1</EventID><EventID>2</EventID>"
        ))
        .is_err());
        assert!(EventMetadata::parse(&format!("<!DOCTYPE Event>{XML}")).is_err());
        let seed = SecurityEvent::heartbeat(Uuid::new_v4(), Uuid::new_v4(), 1, 1000, 1);
        assert!(normalize(XML.into(), "Security", "bookmark".into(), seed).is_err());
    }
}
