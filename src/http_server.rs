use std::{
    env,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex, mpsc},
    thread,
};

pub const ADDRESS_ENV_VAR: &str = "KAGOME_SERVER_ADDRESS";
pub const DEFAULT_ADDRESS: &str = "0.0.0.0:4000";
pub const WORKERS_ENV_VAR: &str = "KAGOME_WORKERS";
pub const DEFAULT_WORKERS: usize = 4;

pub fn address_from_environment() -> String {
    env::var(ADDRESS_ENV_VAR).unwrap_or_else(|_| DEFAULT_ADDRESS.to_owned())
}

pub fn worker_count_from_environment() -> usize {
    worker_count_from_value(env::var(WORKERS_ENV_VAR).ok().as_deref())
}

pub fn worker_count_from_value(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.parse().ok())
        .filter(|worker_count| *worker_count > 0)
        .unwrap_or(DEFAULT_WORKERS)
}

pub fn serve(address: impl ToSocketAddrs) -> io::Result<()> {
    serve_with_workers(address, DEFAULT_WORKERS)
}

pub fn serve_with_workers(address: impl ToSocketAddrs, worker_count: usize) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;

    serve_listener_with_workers(listener, worker_count)
}

pub fn serve_listener_with_workers(listener: TcpListener, worker_count: usize) -> io::Result<()> {
    let worker_count = worker_count.max(1);

    println!("{}", listener.local_addr()?);

    let (sender, receiver) = mpsc::channel();
    let receiver = Arc::new(Mutex::new(receiver));
    let mut workers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let receiver = Arc::clone(&receiver);
        workers.push(thread::spawn(move || worker_loop(receiver)));
    }

    let accept_result = accept_connections(listener, sender.clone());
    drop(sender);

    for worker in workers {
        worker
            .join()
            .map_err(|_| io::Error::other("http server worker panicked"))?;
    }

    accept_result
}

fn accept_connections(listener: TcpListener, sender: mpsc::Sender<TcpStream>) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        sender
            .send(stream)
            .map_err(|_| io::Error::other("http server workers stopped"))?;
    }

    Ok(())
}

fn worker_loop(receiver: Arc<Mutex<mpsc::Receiver<TcpStream>>>) {
    loop {
        let stream = {
            let receiver = receiver
                .lock()
                .expect("http server worker receiver poisoned");
            receiver.recv()
        };

        match stream {
            Ok(stream) => {
                if let Err(error) = handle_connection(stream)
                    && !is_client_disconnect(&error)
                {
                    eprintln!("failed to handle connection: {error}");
                }
            }
            Err(_) => break,
        }
    }
}

fn handle_connection(stream: TcpStream) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    while let Some(request) = read_http_request(&mut reader)? {
        let should_keep_alive = raw_request_connection_keep_alive(&request);
        let mut response = crate::router::route_raw_request(&request);

        if should_keep_alive {
            response = response.replace("connection: close", "connection: keep-alive");
        }

        writer.write_all(response.as_bytes())?;

        if !should_keep_alive {
            break;
        }
    }

    Ok(())
}

pub fn is_client_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
    )
}

fn read_http_request(reader: &mut BufReader<TcpStream>) -> io::Result<Option<String>> {
    let mut request = String::new();
    let mut content_length = 0;

    loop {
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;

        if bytes_read == 0 {
            return if request.is_empty() {
                Ok(None)
            } else {
                Ok(Some(request))
            };
        }

        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or_default();
        }

        let is_end_of_headers = line == "\r\n" || line == "\n";
        request.push_str(&line);

        if is_end_of_headers {
            break;
        }
    }

    let mut body = vec![0; content_length];
    reader.read_exact(&mut body)?;
    request.push_str(&String::from_utf8_lossy(&body));

    Ok(Some(request))
}

fn raw_request_connection_keep_alive(request: &str) -> bool {
    request.lines().any(|line| {
        line.split_once(':')
            .map(|(name, value)| {
                name.eq_ignore_ascii_case("connection")
                    && value.trim().eq_ignore_ascii_case("keep-alive")
            })
            .unwrap_or(false)
    })
}
