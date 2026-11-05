//! Run slow work (Argon2 key derivation) off the UI thread.

use std::sync::mpsc::{self, Receiver, TryRecvError};

use eframe::egui;

pub enum Poll<T> {
    Pending,
    Done(T),
    /// The worker thread panicked.
    Failed,
}

pub struct Job<T> {
    rx: Receiver<T>,
}

impl<T: Send + 'static> Job<T> {
    pub fn spawn(ctx: &egui::Context, work: impl FnOnce() -> T + Send + 'static) -> Self {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = work();
            let _ = tx.send(result);
            ctx.request_repaint();
        });
        Job { rx }
    }

    pub fn poll(&self) -> Poll<T> {
        match self.rx.try_recv() {
            Ok(v) => Poll::Done(v),
            Err(TryRecvError::Empty) => Poll::Pending,
            Err(TryRecvError::Disconnected) => Poll::Failed,
        }
    }
}
