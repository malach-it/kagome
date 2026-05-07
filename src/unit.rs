pub struct KagomeRequest {
    pub protocol: String,
    pub headers: Vec<HttpHeader>,
    pub body: String,
}

pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

pub fn parse_request(request: &str) -> KagomeRequest {
    let (head, body) = split_request(request);
    let mut lines = head.lines();
    let protocol = lines
        .next()
        .and_then(|request_line| request_line.split_whitespace().nth(2))
        .unwrap_or_default()
        .to_owned();

    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| HttpHeader {
            name: name.trim().to_owned(),
            value: value.trim().to_owned(),
        })
        .collect();

    KagomeRequest {
        protocol,
        headers,
        body: body.to_owned(),
    }
}

pub fn to_json(request: &KagomeRequest) -> String {
    let headers = request
        .headers
        .iter()
        .map(|header| {
            format!(
                "{{\"name\":\"{}\",\"value\":\"{}\"}}",
                escape_json(&header.name),
                escape_json(&header.value)
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{\"protocol\":\"{}\",\"headers\":[{}],\"body\":\"{}\"}}",
        escape_json(&request.protocol),
        headers,
        escape_json(&request.body)
    )
}

fn split_request(request: &str) -> (&str, &str) {
    if let Some((head, body)) = request.split_once("\r\n\r\n") {
        (head, body)
    } else if let Some((head, body)) = request.split_once("\n\n") {
        (head, body)
    } else {
        (request, "")
    }
}

fn escape_json(value: &str) -> String {
    value.chars().fold(String::new(), |mut escaped, character| {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }

        escaped
    })
}
