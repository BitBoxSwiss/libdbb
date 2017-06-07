// Copyright (c) 2017 Shift Devices AG
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBDBB_SAFEQUEUE_H
#define LIBDBB_SAFEQUEUE_H

#include <stdint.h>
#include <stdlib.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>

// A threadsafe-queue.
template <class T>
class SafeQueue
{
public:
    SafeQueue(void)
        : q(), m(), c(), shutdownRequested(false)
    {
    }

    ~SafeQueue(void)
    {
    }

    // Add an element to the queue.
    size_t size()
    {
        std::lock_guard<std::mutex> lock(m);
        return q.size();
    }

    // shutdown
    void shutdown()
    {
        shutdownRequested = true;
        c.notify_one();
    }

    bool isShutdown() {
        return shutdownRequested;
    }

    // Add an element to the queue.
    void enqueue(T t)
    {
        std::lock_guard<std::mutex> lock(m);
        q.push(t);
        c.notify_one();
    }

    // Get the "front"-element.
    // If the queue is empty, wait till a element is avaiable.
    T dequeue(void)
    {
        std::unique_lock<std::mutex> lock(m);
        while (q.empty()) {
            // release lock as long as the wait and reaquire it afterwards.
            c.wait(lock);
            if (shutdownRequested) {
                return T();
            }
        }
        T val = q.front();
        q.pop();
        return val;
    }

private:
    std::queue<T> q;
    mutable std::mutex m;
    std::condition_variable c;
    std::atomic<bool> shutdownRequested;
};

#endif // LIBDBB_SAFEQUEUE_H
