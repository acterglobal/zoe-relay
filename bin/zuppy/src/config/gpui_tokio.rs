// Copyright 2022 - 2025 Zed Industries, Inc., 2025 Benjamin Kampmann
//
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//
//  Edited for Stand-alone use outside the ZED repo

use std::future::Future;

use gpui::{App, AppContext, Global, ReadGlobal, Task};
use tokio::task::JoinError;

pub fn init(cx: &mut App) {
    cx.set_global(GlobalTokio::new());
}

pub struct Deferred<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Deferred<F> {
    /// Drop without running the deferred function.
    pub fn abort(mut self) {
        self.0.take();
    }
}

impl<F: FnOnce()> Drop for Deferred<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f()
        }
    }
}

/// Run the given function when the returned value is dropped (unless it's cancelled).
#[must_use]
pub fn defer<F: FnOnce()>(f: F) -> Deferred<F> {
    Deferred(Some(f))
}

struct GlobalTokio {
    runtime: tokio::runtime::Runtime,
}

impl Global for GlobalTokio {}

impl GlobalTokio {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            // Since we now have two executors, let's try to keep our footprint small
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to initialize Tokio");

        Self { runtime }
    }
}

pub struct Tokio {}

impl Tokio {
    /// Spawns the given future on Tokio's thread pool, and returns it via a GPUI task
    /// Note that the Tokio task will be cancelled if the GPUI task is dropped
    pub fn spawn<C, Fut, R>(cx: &C, f: Fut) -> C::Result<Task<Result<R, JoinError>>>
    where
        C: AppContext,
        Fut: Future<Output = R> + Send + 'static,
        R: Send + 'static,
    {
        cx.read_global(|tokio: &GlobalTokio, cx| {
            let join_handle = tokio.runtime.spawn(f);
            let abort_handle = join_handle.abort_handle();
            let cancel = defer(move || {
                abort_handle.abort();
            });
            cx.background_spawn(async move {
                let result = join_handle.await;
                drop(cancel);
                result
            })
        })
    }

    pub fn handle(cx: &App) -> tokio::runtime::Handle {
        GlobalTokio::global(cx).runtime.handle().clone()
    }
}
