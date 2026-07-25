#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};

use encoding_rs::Encoding;
use pdf_extract::Object;
use quick_xml::Reader;
use quick_xml::events::Event;
use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::error::{CrawlError, Result};
use crate::hash::sha256_hex;

pub const EXTRACTOR_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heading {
    pub level: u8,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedLink {
    pub raw_target: String,
    pub resolved_target: Option<String>,
    pub relation: Option<String>,
    pub anchor_text: String,
    pub nofollow: bool,
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractedDocument {
    pub parser: String,
    pub parser_version: String,
    pub media_type: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub language: Option<String>,
    pub canonical_url: Option<String>,
    pub primary_markdown: String,
    pub primary_text: String,
    pub word_count: usize,
    pub headings: Vec<Heading>,
    pub metadata: BTreeMap<String, Value>,
    pub open_graph: BTreeMap<String, String>,
    pub json_ld: Vec<Value>,
    pub schema_types: Vec<String>,
    pub links: Vec<ExtractedLink>,
    pub needs_render: bool,
    pub untrusted_source: bool,
    pub source_sha256: String,
    pub parsed_sha256: String,
}

pub fn extract(bytes: &[u8], content_type: &str, source_url: &Url) -> Result<ExtractedDocument> {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match media_type.as_str() {
        "text/html" | "application/xhtml+xml" => extract_html(bytes, content_type, source_url),
        "application/feed+json" | "application/rss+xml" | "application/atom+xml" => {
            extract_feed(bytes, &media_type, source_url)
        }
        "application/json" | "application/ld+json" => extract_json(bytes, &media_type),
        "application/xml" | "text/xml" if looks_like_feed(bytes) => {
            extract_feed(bytes, &media_type, source_url)
        }
        "application/xml" | "text/xml" => extract_xml(bytes, &media_type),
        "application/pdf" => extract_pdf(bytes),
        value if value.starts_with("text/") || value.is_empty() => {
            Ok(extract_text(bytes, content_type, &media_type))
        }
        _ => Err(CrawlError::Parser(format!(
            "unsupported media type {media_type}"
        ))),
    }
}

fn extract_html(bytes: &[u8], content_type: &str, source_url: &Url) -> Result<ExtractedDocument> {
    let source = decode_text(bytes, content_type);
    let document = Html::parse_document(&source);
    let title = first_text(&document, "title")
        .or_else(|| meta_content(&document, "meta[property='og:title']"));
    let description = meta_content(&document, "meta[name='description']")
        .or_else(|| meta_content(&document, "meta[property='og:description']"));
    let author = meta_content(&document, "meta[name='author']");
    let language = document
        .select(&selector("html")?)
        .next()
        .and_then(|element| element.value().attr("lang"))
        .map(str::to_owned);
    let canonical_url = document
        .select(&selector("link[rel~='canonical']")?)
        .next()
        .and_then(|element| element.value().attr("href"))
        .and_then(|href| source_url.join(href).ok())
        .map(|url| url.to_string());
    let robots = meta_content(&document, "meta[name='robots']");
    let mut published_at_utc = meta_content(&document, "meta[property='article:published_time']")
        .or_else(|| meta_content(&document, "meta[name='date']"));
    let mut modified_at_utc = meta_content(&document, "meta[property='article:modified_time']")
        .or_else(|| meta_content(&document, "meta[name='last-modified']"));

    let content_selector = selector("article, main")?;
    let body_selector = selector("body")?;
    let root = document
        .select(&content_selector)
        .max_by_key(|element| visible_text(element).len())
        .or_else(|| document.select(&body_selector).next());
    let root_html = root.map_or_else(|| source.clone(), |element| element.html());
    let primary_markdown = normalize_blank_lines(&html2md::parse_html(&root_html));
    let primary_text = root.map_or_else(String::new, |element| visible_text(&element));
    let word_count = primary_text.split_whitespace().count();

    let mut headings = Vec::new();
    for level in 1..=6 {
        for heading in document.select(&selector(&format!("h{level}"))?) {
            let text = clean_text(heading.text());
            if !text.is_empty() {
                headings.push(Heading { level, text });
            }
        }
    }

    let mut open_graph = BTreeMap::new();
    for element in document.select(&selector("meta[property^='og:']")?) {
        if let (Some(property), Some(content)) = (
            element.value().attr("property"),
            element.value().attr("content"),
        ) {
            open_graph.insert(property.to_owned(), content.to_owned());
        }
    }

    let mut json_ld = Vec::new();
    let mut schema_types = BTreeSet::new();
    for script in document.select(&selector("script[type='application/ld+json']")?) {
        let raw = script.text().collect::<String>();
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            collect_schema_types(&value, &mut schema_types);
            published_at_utc = published_at_utc
                .or_else(|| find_json_string(&value, &["datePublished", "dateCreated"]));
            modified_at_utc =
                modified_at_utc.or_else(|| find_json_string(&value, &["dateModified"]));
            json_ld.push(value);
        }
    }

    let mut links = Vec::new();
    for anchor in document.select(&selector("a[href]")?) {
        let Some(raw_target) = anchor.value().attr("href") else {
            continue;
        };
        let resolved = source_url.join(raw_target).ok();
        let relation = anchor.value().attr("rel").map(str::to_owned);
        let nofollow = relation.as_deref().is_some_and(|value| {
            value
                .split_ascii_whitespace()
                .any(|item| item == "nofollow")
        });
        let classification = resolved.as_ref().map_or("unknown", |target| {
            if source_url.scheme() == target.scheme()
                && source_url.host_str() == target.host_str()
                && source_url.port_or_known_default() == target.port_or_known_default()
            {
                "internal"
            } else {
                "external"
            }
        });
        links.push(ExtractedLink {
            raw_target: raw_target.to_owned(),
            resolved_target: resolved.map(|url| url.to_string()),
            relation,
            anchor_text: clean_text(anchor.text()),
            nofollow,
            classification: classification.to_owned(),
        });
    }

    let script_count = document.select(&selector("script[src]")?).count();
    let form_count = document.select(&selector("form")?).count();
    let image_count = document.select(&selector("img")?).count();
    let table_count = document.select(&selector("table")?).count();
    let client_markers = [
        "__NEXT_DATA__",
        "data-reactroot",
        "ng-version",
        "id=\"app\"",
    ]
    .iter()
    .filter(|marker| source.contains(*marker))
    .count();
    let needs_render = word_count < 40 && (script_count >= 2 || client_markers > 0);
    let mut metadata = BTreeMap::new();
    metadata.insert("script_count".to_owned(), json!(script_count));
    metadata.insert("form_count".to_owned(), json!(form_count));
    metadata.insert("image_count".to_owned(), json!(image_count));
    metadata.insert("table_count".to_owned(), json!(table_count));
    metadata.insert("client_render_markers".to_owned(), json!(client_markers));
    metadata.insert("robots".to_owned(), json!(robots));
    metadata.insert("published_at_utc".to_owned(), json!(published_at_utc));
    metadata.insert("modified_at_utc".to_owned(), json!(modified_at_utc));

    let hreflang = document
        .select(&selector("link[rel~='alternate'][hreflang][href]")?)
        .map(|element| {
            let raw_target = element.value().attr("href").unwrap_or_default();
            json!({
                "language": element.value().attr("hreflang"),
                "raw_target": raw_target,
                "resolved_target": source_url.join(raw_target).ok().map(|url| url.to_string()),
            })
        })
        .collect::<Vec<_>>();
    metadata.insert("hreflang".to_owned(), json!(hreflang));

    let pagination = document
        .select(&selector(
            "link[rel~='prev'][href], link[rel~='next'][href]",
        )?)
        .map(|element| {
            let raw_target = element.value().attr("href").unwrap_or_default();
            json!({
                "relation": element.value().attr("rel"),
                "raw_target": raw_target,
                "resolved_target": source_url.join(raw_target).ok().map(|url| url.to_string()),
            })
        })
        .collect::<Vec<_>>();
    metadata.insert("pagination".to_owned(), json!(pagination));

    let images = document
        .select(&selector("img")?)
        .map(|element| {
            let raw_target = element.value().attr("src");
            json!({
                "raw_target": raw_target,
                "resolved_target": raw_target.and_then(|target| source_url.join(target).ok()).map(|url| url.to_string()),
                "alt": element.value().attr("alt"),
                "width": element.value().attr("width"),
                "height": element.value().attr("height"),
            })
        })
        .collect::<Vec<_>>();
    metadata.insert("images".to_owned(), json!(images));

    let forms = document
        .select(&selector("form")?)
        .map(|element| {
            let raw_action = element.value().attr("action");
            json!({
                "raw_action": raw_action,
                "resolved_action": raw_action.and_then(|target| source_url.join(target).ok()).map(|url| url.to_string()),
                "method": element.value().attr("method").unwrap_or("get").to_ascii_lowercase(),
            })
        })
        .collect::<Vec<_>>();
    metadata.insert("forms".to_owned(), json!(forms));

    let row_selector = selector("tr")?;
    let cell_selector = selector("th, td")?;
    let tables = document
        .select(&selector("table")?)
        .map(|table| {
            let rows = table.select(&row_selector).collect::<Vec<_>>();
            let max_columns = rows
                .iter()
                .map(|row| row.select(&cell_selector).count())
                .max()
                .unwrap_or_default();
            json!({"row_count": rows.len(), "max_column_count": max_columns})
        })
        .collect::<Vec<_>>();
    metadata.insert("tables".to_owned(), json!(tables));

    let microdata_types = document
        .select(&selector("[itemscope][itemtype]")?)
        .flat_map(|element| {
            element
                .value()
                .attr("itemtype")
                .unwrap_or_default()
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    metadata.insert("microdata_types".to_owned(), json!(microdata_types));

    Ok(finalize(
        "html",
        "text/html",
        bytes,
        title,
        description,
        author,
        language,
        canonical_url,
        primary_markdown,
        primary_text,
        headings,
        metadata,
        open_graph,
        json_ld,
        schema_types.into_iter().collect(),
        links,
        needs_render,
    ))
}

fn extract_json(bytes: &[u8], media_type: &str) -> Result<ExtractedDocument> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| CrawlError::Parser(format!("invalid JSON: {error}")))?;
    let pretty = serde_json::to_string_pretty(&value)?;
    let mut schema_types = BTreeSet::new();
    collect_schema_types(&value, &mut schema_types);
    Ok(finalize(
        "json",
        media_type,
        bytes,
        value
            .get("title")
            .and_then(Value::as_str)
            .map(str::to_owned),
        None,
        None,
        None,
        None,
        format!("```json\n{pretty}\n```\n"),
        pretty,
        Vec::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        vec![value],
        schema_types.into_iter().collect(),
        Vec::new(),
        false,
    ))
}

fn extract_xml(bytes: &[u8], media_type: &str) -> Result<ExtractedDocument> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().check_end_names = true;
    let mut text = String::new();
    let mut element_count = 0_usize;
    loop {
        match reader.read_event() {
            Ok(Event::Start(_) | Event::Empty(_)) => element_count += 1,
            Ok(Event::Text(value)) => {
                let decoded = value
                    .decode()
                    .map_err(|error| CrawlError::Parser(format!("XML text decode: {error}")))?;
                let cleaned = decoded.trim();
                if !cleaned.is_empty() {
                    text.push_str(cleaned);
                    text.push('\n');
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(CrawlError::Parser(format!("invalid XML: {error}"))),
            _ => {}
        }
    }
    let mut metadata = BTreeMap::new();
    metadata.insert("element_count".to_owned(), json!(element_count));
    Ok(finalize(
        "xml",
        media_type,
        bytes,
        None,
        None,
        None,
        None,
        None,
        text.clone(),
        text,
        Vec::new(),
        metadata,
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        false,
    ))
}

fn looks_like_feed(bytes: &[u8]) -> bool {
    let prefix = String::from_utf8_lossy(&bytes[..bytes.len().min(1024)]).to_ascii_lowercase();
    prefix.contains("<rss")
        || prefix.contains("<feed")
        || prefix.contains("\"version\":\"https://jsonfeed.org/")
}

fn feed_enclosures(entry: &feed_rs::model::Entry) -> Vec<Value> {
    let mut enclosures = entry
        .links
        .iter()
        .filter(|link| link.rel.as_deref() == Some("enclosure"))
        .map(|link| {
            json!({
                "url": link.href,
                "media_type": link.media_type,
                "length": link.length,
                "title": link.title,
            })
        })
        .collect::<Vec<_>>();
    enclosures.extend(entry.media.iter().flat_map(|media| {
        media.content.iter().filter_map(|content| {
            content.url.as_ref().map(|url| {
                json!({
                    "url": url,
                    "media_type": content.content_type.as_ref().map(ToString::to_string),
                    "length": content.size,
                    "title": media.title.as_ref().map(|title| title.content.as_str()),
                })
            })
        })
    }));
    enclosures
}

fn extract_feed(bytes: &[u8], media_type: &str, source_url: &Url) -> Result<ExtractedDocument> {
    let feed = feed_rs::parser::parse(bytes)
        .map_err(|error| CrawlError::Parser(format!("invalid feed: {error}")))?;
    let title = feed.title.as_ref().map(|value| value.content.clone());
    let description = feed.description.as_ref().map(|value| value.content.clone());
    let author = feed
        .authors
        .iter()
        .map(|person| person.name.trim())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    let author = (!author.is_empty()).then_some(author);
    let mut primary_text = String::new();
    let mut links = Vec::new();
    for entry in &feed.entries {
        if let Some(entry_title) = &entry.title {
            primary_text.push_str(&entry_title.content);
            primary_text.push('\n');
        }
        if let Some(summary) = &entry.summary {
            primary_text.push_str(&summary.content);
            primary_text.push('\n');
        }
        for link in &entry.links {
            let resolved = source_url.join(&link.href).ok();
            links.push(ExtractedLink {
                raw_target: link.href.clone(),
                resolved_target: resolved.as_ref().map(Url::to_string),
                relation: link.rel.clone(),
                anchor_text: entry
                    .title
                    .as_ref()
                    .map_or_else(String::new, |value| value.content.clone()),
                nofollow: false,
                classification: resolved.as_ref().map_or_else(
                    || "unknown".to_owned(),
                    |target| {
                        if source_url.host_str() == target.host_str() {
                            "internal".to_owned()
                        } else {
                            "external".to_owned()
                        }
                    },
                ),
            });
        }
    }
    let mut metadata = BTreeMap::new();
    metadata.insert("feed_id".to_owned(), json!(feed.id));
    metadata.insert(
        "feed_type".to_owned(),
        json!(format!("{:?}", feed.feed_type)),
    );
    metadata.insert("entry_count".to_owned(), json!(feed.entries.len()));
    metadata.insert(
        "continuation".to_owned(),
        json!({
            "next_url": feed.links.iter().find(|link| link.rel.as_deref() == Some("next")).map(|link| link.href.as_str()),
            "complete": !feed.links.iter().any(|link| link.rel.as_deref() == Some("next")),
        }),
    );
    metadata.insert(
        "entries".to_owned(),
        Value::Array(
            feed.entries
                .iter()
                .map(|entry| {
                    json!({
                        "id":entry.id,
                        "title":entry.title.as_ref().map(|value| value.content.as_str()),
                        "links":entry.links.iter().map(|link| link.href.as_str()).collect::<Vec<_>>(),
                        "source_url":entry.source.as_deref().or_else(|| entry.links.iter().find(|link| link.rel.as_deref().is_none_or(|rel| rel == "alternate")).map(|link| link.href.as_str())),
                        "published_at_utc":entry.published,
                        "updated_at_utc":entry.updated,
                        "authors":entry.authors.iter().map(|person| person.name.as_str()).collect::<Vec<_>>(),
                        "categories":entry.categories.iter().map(|category| json!({
                            "term": category.term,
                            "scheme": category.scheme,
                            "label": category.label,
                        })).collect::<Vec<_>>(),
                        "enclosures": feed_enclosures(entry),
                    })
                })
                .collect(),
        ),
    );
    let markdown = primary_text
        .lines()
        .map(|line| format!("- {}", line.trim()))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(finalize(
        "feed-rs",
        media_type,
        bytes,
        title,
        description,
        author,
        feed.language,
        None,
        markdown,
        primary_text,
        Vec::new(),
        metadata,
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
        links,
        false,
    ))
}

fn extract_pdf(bytes: &[u8]) -> Result<ExtractedDocument> {
    if !bytes.starts_with(b"%PDF-") {
        return Err(CrawlError::Parser("invalid PDF signature".to_owned()));
    }
    let text = pdf_extract::extract_text_from_mem(bytes)
        .map_err(|error| CrawlError::Parser(format!("PDF extraction failed: {error}")))?;
    let pdf_document = pdf_extract::Document::load_mem(bytes)
        .map_err(|error| CrawlError::Parser(format!("PDF metadata failed: {error}")))?;
    let page_count = pdf_document.get_pages().len();
    let requires_ocr = text.split_whitespace().count() < 10;
    let mut metadata = BTreeMap::new();
    metadata.insert("page_count".to_owned(), json!(page_count));
    metadata.insert("requires_ocr".to_owned(), json!(requires_ocr));
    metadata.insert("page_boundary".to_owned(), json!("form-feed"));
    let pages = text
        .split('\u{c}')
        .enumerate()
        .map(|(index, page_text)| {
            json!({
                "page_number": index.saturating_add(1),
                "text": page_text,
                "text_sha256": sha256_hex(page_text.as_bytes()),
                "word_count": page_text.split_whitespace().count(),
            })
        })
        .collect::<Vec<_>>();
    metadata.insert("pages".to_owned(), json!(pages));

    let mut document_metadata = BTreeMap::new();
    if let Ok(info_reference) = pdf_document
        .trailer
        .get(b"Info")
        .and_then(Object::as_reference)
        && let Ok(info) = pdf_document.get_dictionary(info_reference)
    {
        for key in [
            b"Title".as_slice(),
            b"Author".as_slice(),
            b"Subject".as_slice(),
            b"Keywords".as_slice(),
            b"Creator".as_slice(),
            b"Producer".as_slice(),
            b"CreationDate".as_slice(),
            b"ModDate".as_slice(),
        ] {
            if let Ok(value) = info.get(key)
                && let Ok((_, value)) = pdf_document.dereference(value)
                && let Ok(raw) = value.as_str()
            {
                document_metadata.insert(
                    String::from_utf8_lossy(key).into_owned(),
                    String::from_utf8_lossy(raw).into_owned(),
                );
            }
        }
    }
    metadata.insert("document_metadata".to_owned(), json!(document_metadata));
    Ok(finalize(
        "pdf-extract",
        "application/pdf",
        bytes,
        None,
        None,
        None,
        None,
        None,
        text.clone(),
        text,
        Vec::new(),
        metadata,
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        false,
    ))
}

fn extract_text(bytes: &[u8], content_type: &str, media_type: &str) -> ExtractedDocument {
    let text = decode_text(bytes, content_type);
    finalize(
        "plain-text",
        if media_type.is_empty() {
            "text/plain"
        } else {
            media_type
        },
        bytes,
        None,
        None,
        None,
        None,
        None,
        text.clone(),
        text,
        Vec::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn finalize(
    parser: &str,
    media_type: &str,
    bytes: &[u8],
    title: Option<String>,
    description: Option<String>,
    author: Option<String>,
    language: Option<String>,
    canonical_url: Option<String>,
    primary_markdown: String,
    primary_text: String,
    headings: Vec<Heading>,
    metadata: BTreeMap<String, Value>,
    open_graph: BTreeMap<String, String>,
    json_ld: Vec<Value>,
    schema_types: Vec<String>,
    links: Vec<ExtractedLink>,
    needs_render: bool,
) -> ExtractedDocument {
    let word_count = primary_text.split_whitespace().count();
    let parsed_sha256 = sha256_hex(primary_text.as_bytes());
    ExtractedDocument {
        parser: parser.to_owned(),
        parser_version: EXTRACTOR_VERSION.to_owned(),
        media_type: media_type.to_owned(),
        title,
        description,
        author,
        language,
        canonical_url,
        primary_markdown,
        primary_text,
        word_count,
        headings,
        metadata,
        open_graph,
        json_ld,
        schema_types,
        links,
        needs_render,
        untrusted_source: true,
        source_sha256: sha256_hex(bytes),
        parsed_sha256,
    }
}

fn selector(value: &str) -> Result<Selector> {
    Selector::parse(value)
        .map_err(|error| CrawlError::Parser(format!("invalid built-in selector: {error}")))
}

fn first_text(document: &Html, value: &str) -> Option<String> {
    let selector = Selector::parse(value).ok()?;
    document
        .select(&selector)
        .next()
        .map(|element| clean_text(element.text()))
        .filter(|text| !text.is_empty())
}

fn meta_content(document: &Html, value: &str) -> Option<String> {
    let selector = Selector::parse(value).ok()?;
    document
        .select(&selector)
        .next()
        .and_then(|element| element.value().attr("content"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn visible_text(element: &ElementRef<'_>) -> String {
    clean_text(element.text())
}

fn clean_text<'a>(values: impl Iterator<Item = &'a str>) -> String {
    values
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_blank_lines(value: &str) -> String {
    let mut output = String::new();
    let mut prior_blank = false;
    for line in value.lines() {
        let blank = line.trim().is_empty();
        if blank && prior_blank {
            continue;
        }
        output.push_str(line.trim_end());
        output.push('\n');
        prior_blank = blank;
    }
    output
}

fn decode_text(bytes: &[u8], content_type: &str) -> String {
    let label = content_type.split(';').skip(1).find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        key.eq_ignore_ascii_case("charset")
            .then(|| value.trim_matches(['\'', '"']).as_bytes())
    });
    let encoding = label
        .and_then(Encoding::for_label)
        .unwrap_or(encoding_rs::UTF_8);
    let (decoded, _, _) = encoding.decode(bytes);
    decoded.into_owned()
}

fn collect_schema_types(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if let Some(kind) = map.get("@type") {
                match kind {
                    Value::String(value) => {
                        output.insert(value.clone());
                    }
                    Value::Array(values) => {
                        for value in values.iter().filter_map(Value::as_str) {
                            output.insert(value.to_owned());
                        }
                    }
                    _ => {}
                }
            }
            for child in map.values() {
                collect_schema_types(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_schema_types(child, output);
            }
        }
        _ => {}
    }
}

fn find_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(found) = map.get(*key).and_then(Value::as_str) {
                    return Some(found.to_owned());
                }
            }
            map.values().find_map(|child| find_json_string(child, keys))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|child| find_json_string(child, keys)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::extract;
    use crate::hash::sha256_hex;

    #[test]
    fn article_fixture_preserves_provenance_and_links() {
        let bytes = include_bytes!("../../../fixtures/http/article.html");
        let url = url::Url::parse("https://example.com/article").expect("URL");
        let document = extract(bytes, "text/html; charset=utf-8", &url).expect("extract");
        assert!(document.untrusted_source);
        assert!(document.word_count > 10);
        assert!(!document.source_sha256.is_empty());
        assert!(!document.links.is_empty());
        assert_eq!(document.metadata["robots"], "index,follow,max-snippet:-1");
        assert_eq!(
            document.metadata["published_at_utc"],
            "2026-07-19T12:00:00Z"
        );
        assert_eq!(
            document.metadata["hreflang"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            document.metadata["pagination"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            document.metadata["images"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            document.metadata["tables"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(document.metadata["forms"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            document.metadata["microdata_types"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn js_shell_is_marked_for_manual_rendering() {
        let bytes = include_bytes!("../../../fixtures/http/js-shell.html");
        let url = url::Url::parse("https://example.com/app").expect("URL");
        let document = extract(bytes, "text/html", &url).expect("extract");
        assert!(document.needs_render);
    }

    #[test]
    fn malformed_json_is_typed_failure() {
        let bytes = include_bytes!("../../../fixtures/http/malformed.json");
        let url = url::Url::parse("https://example.com/data.json").expect("URL");
        assert!(extract(bytes, "application/json", &url).is_err());
    }

    #[test]
    fn rss_and_atom_preserve_feed_entries() {
        let url = url::Url::parse("https://example.com/feed").expect("URL");
        for (bytes, media_type) in [
            (
                include_bytes!("../../../fixtures/http/feed.rss").as_slice(),
                "application/rss+xml",
            ),
            (
                include_bytes!("../../../fixtures/http/feed.atom").as_slice(),
                "application/atom+xml",
            ),
        ] {
            let document = extract(bytes, media_type, &url).expect("extract feed");
            assert_eq!(document.parser, "feed-rs");
            assert!(
                document.metadata["entry_count"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
            );
            assert!(!document.primary_text.is_empty());
            let entry = &document.metadata["entries"][0];
            assert!(entry["source_url"].as_str().is_some());
            assert_eq!(entry["categories"].as_array().map(Vec::len), Some(1));
            assert_eq!(entry["enclosures"].as_array().map(Vec::len), Some(1));
        }
        let atom = extract(
            include_bytes!("../../../fixtures/http/feed.atom"),
            "application/atom+xml",
            &url,
        )
        .expect("Atom continuation");
        assert_eq!(atom.metadata["continuation"]["complete"], false);
        assert_eq!(
            atom.metadata["continuation"]["next_url"],
            "https://fixture.invalid/feed?page=2"
        );
    }

    #[test]
    fn promoted_phase_one_formats_have_offline_golden_extraction() {
        let url = url::Url::parse("https://example.com/fixture").expect("URL");
        for bytes in [
            include_bytes!("../../../fixtures/http/article.html").as_slice(),
            include_bytes!("../../../fixtures/http/navigation-heavy.html").as_slice(),
            include_bytes!("../../../fixtures/http/malformed.html").as_slice(),
            include_bytes!("../../../fixtures/http/jsonld-article.html").as_slice(),
            include_bytes!("../../../fixtures/http/table.html").as_slice(),
            include_bytes!("../../../fixtures/http/duplicate-headings.html").as_slice(),
            include_bytes!("../../../fixtures/http/non-english.html").as_slice(),
            include_bytes!("../../../fixtures/http/charset-conflict.html").as_slice(),
            include_bytes!("../../../fixtures/http/prompt-injection.html").as_slice(),
            include_bytes!("../../../fixtures/http/js-shell.html").as_slice(),
        ] {
            let document = extract(bytes, "text/html; charset=utf-8", &url).expect("HTML golden");
            assert_eq!(document.parser, "html");
            assert!(document.untrusted_source);
            assert_eq!(document.source_sha256, sha256_hex(bytes));
        }
        let json = extract(
            include_bytes!("../../../fixtures/http/valid.json"),
            "application/json",
            &url,
        )
        .expect("JSON golden");
        assert_eq!(json.parser, "json");

        let sitemap = extract(
            include_bytes!("../../../fixtures/http/sitemap.xml"),
            "application/xml",
            &url,
        )
        .expect("XML golden");
        assert_eq!(sitemap.parser, "xml");
        assert!(
            sitemap.metadata["element_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
        );

        let pdf = extract(
            include_bytes!("../../../fixtures/http/text.pdf"),
            "application/pdf",
            &url,
        )
        .expect("PDF golden");
        assert_eq!(pdf.parser, "pdf-extract");
        assert!(pdf.primary_text.contains("Phase One PDF Fixture Text"));
        assert_eq!(pdf.metadata["page_count"], 1);
        assert_eq!(pdf.metadata["pages"].as_array().map(Vec::len), Some(1));
        assert!(pdf.metadata["document_metadata"].is_object());
    }

    #[test]
    fn every_promoted_phase_one_format_matches_exact_whole_document_golden() {
        let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/http");
        let expected: serde_json::Value = serde_json::from_slice(
            &fs::read(fixture_root.join("../expected/phase1-extraction.v1.json"))
                .expect("golden manifest"),
        )
        .expect("parse golden manifest");
        let expected = expected.as_object().expect("golden object");
        assert_eq!(expected.len(), 7);
        let source_url = url::Url::parse("https://example.com/golden").expect("source URL");
        for (name, value) in expected {
            let file = value["file"].as_str().expect("golden file");
            let content_type = value["content_type"].as_str().expect("golden content type");
            let bytes = fs::read(fixture_root.join(file)).expect("fixture bytes");
            let document = extract(&bytes, content_type, &source_url).expect("golden extraction");
            assert_eq!(
                document.parser,
                value["parser"].as_str().unwrap_or_default(),
                "{name}"
            );
            assert_eq!(document.source_sha256, value["source_sha256"], "{name}");
            assert_eq!(document.parsed_sha256, value["parsed_sha256"], "{name}");
            assert_eq!(
                document.word_count,
                usize::try_from(value["word_count"].as_u64().unwrap_or_default())
                    .expect("word count fits usize"),
                "{name}"
            );
            assert_eq!(
                document.needs_render,
                value["needs_render"].as_bool().unwrap_or(true),
                "{name}"
            );
            let document_hash =
                sha256_hex(&serde_json::to_vec(&document).expect("serialize extracted document"));
            assert_eq!(document_hash, value["document_sha256"], "{name}");
        }
    }
}
