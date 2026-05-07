#[derive(Debug)]
pub struct KagomeRequest {
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub headers: Vec<HttpHeader>,
    pub body: String,
}

#[derive(Debug)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

pub fn parse_request(request: &str) -> KagomeRequest {
    let (head, body) = split_request(request);
    let mut lines = head.lines();
    let (method, path, protocol) = lines
        .next()
        .map(parse_request_line)
        .unwrap_or_else(|| ("".to_owned(), "".to_owned(), "".to_owned()));

    let headers: Vec<HttpHeader> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| HttpHeader {
            name: name.trim().to_owned(),
            value: value.trim().to_owned(),
        })
        .collect();
    KagomeRequest {
        method,
        path,
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
        "{{\"method\":\"{}\",\"path\":\"{}\",\"protocol\":\"{}\",\"headers\":[{}],\"body\":\"{}\"}}",
        escape_json(&request.method),
        escape_json(&request.path),
        escape_json(&request.protocol),
        headers,
        escape_json(&request.body)
    )
}

pub fn parse_request_parameter(request: &KagomeRequest, parameter_name: &str) -> Option<String> {
    parse_body_string_parameter(
        &request.method,
        &request.headers,
        &request.body,
        parameter_name,
    )
}

fn parse_body_string_parameter(
    method: &str,
    headers: &[HttpHeader],
    body: &str,
    parameter_name: &str,
) -> Option<String> {
    if !method.eq_ignore_ascii_case("POST") {
        return None;
    }

    let content_type = content_type(headers)?;
    let media_type = content_type
        .split_once(';')
        .map(|(media_type, _)| media_type)
        .unwrap_or(content_type)
        .trim();

    if media_type.eq_ignore_ascii_case("application/json") {
        return parse_json_string_parameter(body, parameter_name);
    }

    if media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded")
        || media_type.eq_ignore_ascii_case("application/www-form-urlencoded")
    {
        return parse_form_parameter(body, parameter_name);
    }

    None
}

fn content_type(headers: &[HttpHeader]) -> Option<&str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| header.value.as_str())
}

fn parse_form_parameter(body: &str, parameter_name: &str) -> Option<String> {
    body.split('&').find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;

        if name == parameter_name {
            Some(decode_form_value(value))
        } else {
            None
        }
    })
}

fn parse_json_string_parameter(body: &str, parameter_name: &str) -> Option<String> {
    let mut index = skip_json_whitespace(body.as_bytes(), 0);

    if body.as_bytes().get(index) != Some(&b'{') {
        return None;
    }

    index += 1;

    loop {
        index = skip_json_whitespace(body.as_bytes(), index);

        match body.as_bytes().get(index) {
            Some(b'}') | None => return None,
            Some(b'"') => {}
            _ => return None,
        }

        let (name, next_index) = parse_json_string(body, index)?;
        index = skip_json_whitespace(body.as_bytes(), next_index);

        if body.as_bytes().get(index) != Some(&b':') {
            return None;
        }

        index = skip_json_whitespace(body.as_bytes(), index + 1);

        if name == parameter_name {
            return parse_json_string(body, index).map(|(value, _)| value);
        }

        index = skip_json_value(body, index)?;
        index = skip_json_whitespace(body.as_bytes(), index);

        match body.as_bytes().get(index) {
            Some(b',') => index += 1,
            Some(b'}') | None => return None,
            _ => return None,
        }
    }
}

fn parse_json_string(body: &str, start: usize) -> Option<(String, usize)> {
    let bytes = body.as_bytes();

    if bytes.get(start) != Some(&b'"') {
        return None;
    }

    let mut value = String::new();
    let mut index = start + 1;

    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Some((value, index + 1)),
            b'\\' => {
                index += 1;
                let escaped = *bytes.get(index)?;
                match escaped {
                    b'"' => value.push('"'),
                    b'\\' => value.push('\\'),
                    b'/' => value.push('/'),
                    b'b' => value.push('\u{0008}'),
                    b'f' => value.push('\u{000c}'),
                    b'n' => value.push('\n'),
                    b'r' => value.push('\r'),
                    b't' => value.push('\t'),
                    _ => return None,
                }
            }
            byte => value.push(byte as char),
        }

        index += 1;
    }

    None
}

fn skip_json_value(body: &str, start: usize) -> Option<usize> {
    let bytes = body.as_bytes();
    let index = skip_json_whitespace(bytes, start);

    match bytes.get(index)? {
        b'"' => parse_json_string(body, index).map(|(_, index)| index),
        b'{' => skip_json_container(bytes, index, b'{', b'}'),
        b'[' => skip_json_container(bytes, index, b'[', b']'),
        _ => {
            let end = body[index..]
                .find([',', '}'])
                .map(|offset| index + offset)
                .unwrap_or(bytes.len());
            Some(end)
        }
    }
}

fn skip_json_container(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0;
    let mut index = start;
    let mut in_string = false;
    let mut escaped = false;

    while index < bytes.len() {
        let byte = bytes[index];

        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == open {
            depth += 1;
        } else if byte == close {
            depth -= 1;

            if depth == 0 {
                return Some(index + 1);
            }
        }

        index += 1;
    }

    None
}

fn skip_json_whitespace(bytes: &[u8], start: usize) -> usize {
    let mut index = start;

    while bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        index += 1;
    }

    index
}

fn decode_form_value(value: &str) -> String {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let Some(byte) = decode_hex_byte(bytes[index + 1], bytes[index + 2]) {
                    decoded.push(byte);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

fn decode_hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(decode_hex_digit(high)? * 16 + decode_hex_digit(low)?)
}

fn decode_hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

fn parse_request_line(request_line: &str) -> (String, String, String) {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let protocol = parts.next().unwrap_or_default().to_owned();

    (method, path, protocol)
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
