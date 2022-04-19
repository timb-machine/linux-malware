// Copyright (c) 2020 VMWare, Inc. All rights reserved.
// SPDX-License-Identifier: GPL-2.0

#include "BpfApi.h"

/* Building directly with cmake will expect these libraries in the default
 * locations associated with bcc, but building with the internal CB build
 * utility expects the packaged location of this header to be slightly different
 */
#ifdef LOCAL_BUILD
#include <bcc/BPF.h>
#else
#include <BPF.h>
#endif
#include <climits>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <chrono>

using namespace cb_endpoint::bpf_probe;
using namespace std::chrono;

#define DEBUG_ORDER(BLOCK)
//#define DEBUG_ORDER(BLOCK) BLOCK while(0)

#define DEBUG_HARVEST(BLOCK)
//#define DEBUG_HARVEST(BLOCK) BLOCK while(0)

BpfApi::BpfApi()
    : m_BPF(nullptr)
    , m_kptr_restrict_path("/proc/sys/kernel/kptr_restrict")
    , m_bracket_kptr_restrict(false)
    , m_first_syscall_lookup(true)
    , m_kptr_restrict_orig(0)
    , m_event_list()
    , m_timestamp_last(0)
    , m_event_count(0)
    , m_did_leave_events(false)
{
}

BpfApi::~BpfApi()
{
}

void BpfApi::CleanBuildDir()
{
    // delete the contents of the directory /var/tmp/bcc
    // resolves DSEN-13711
    IGNORE_UNUSED_RETURN_VALUE(system("rm -rf /var/tmp/bcc"));
}

bool BpfApi::Init(const std::string & bpf_program)
{
    m_BPF = std::unique_ptr<ebpf::BPF>(new ebpf::BPF());
    if (!m_BPF)
    {
        return false;
    }

    bool kptr_result = GetKptrRestrict(m_kptr_restrict_orig);
    if (kptr_result && m_kptr_restrict_orig >= 2)
    {
        m_bracket_kptr_restrict = true;
    }

    CleanBuildDir();

    auto result = m_BPF->init(bpf_program, {}, {});
    if (!result.ok())
    {
        m_ErrorMessage = result.msg();
    }

    return result.ok();
}

void BpfApi::Reset()
{
    // Calling ebpf::BPF::detach_all multiple times on the same object results in double free and segfault.
    // ebpf::BPF::~BPF calls detach_all so the best thing is to delete the object.
    if (m_BPF)
    {
        m_BPF.reset();
    }
}


// When we need to lower kptr_restrict we only have to do it once.
// Alternatively we could manually guess what the name of the syscall prefix
// without changing kptr_restrict but would need  more work to do cleanly.
void BpfApi::LookupSyscallName(const char * name, std::string & syscall_name)
{
    if (!name)
    {
        return;
    }

    if (m_BPF)
    {
        if (m_first_syscall_lookup)
        {
            LowerKptrRestrict();
        }
        syscall_name = m_BPF->get_syscall_fnname(name);
        if (m_first_syscall_lookup)
        {
            RaiseKptrRestrict();
            m_first_syscall_lookup = false;
        }
    }
    else
    {
        syscall_name = std::string(name);
    }
}

bool BpfApi::AttachProbe(const char * name,
                         const char * callback,
                         ProbeType    type)
{
    if (!m_BPF)
    {
        return false;
    }

    std::string           alternate;
    bpf_probe_attach_type attach_type;
    switch (type)
    {
    case ProbeType::LookupEntry:
        LookupSyscallName(name, alternate);
        name = alternate.c_str();
        // https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html#index-Wimplicit-fallthrough
        [[fallthrough]];
    case ProbeType::Entry:
        attach_type = BPF_PROBE_ENTRY;
        break;
    case ProbeType::LookupReturn:
        LookupSyscallName(name, alternate);
        name = alternate.c_str();
        // https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html#index-Wimplicit-fallthrough
        [[fallthrough]];
    case ProbeType::Return:
        attach_type = BPF_PROBE_RETURN;
        break;
    case ProbeType::Tracepoint:
    {
        auto result = m_BPF->attach_tracepoint(name, callback);
        if (!result.ok())
        {
            m_ErrorMessage = result.msg();
        }

        return result.ok();
    }
    default:
        return false;
    }

    auto result = m_BPF->attach_kprobe(
            name,
            callback,
            0,
            attach_type);

    if (!result.ok())
    {
        m_ErrorMessage = result.msg();
    }

    return result.ok();
}

bool BpfApi::RegisterEventCallback(EventCallbackFn callback)
{
    if (!m_BPF)
    {
        return false;
    }

    m_eventCallbackFn = std::move(callback);

    // Trying 1024 pages so we don't drop so many events, no dropped
    // even callback for now.
    auto result = m_BPF->open_perf_buffer(
            "events", on_perf_submit, on_perf_peek, nullptr, static_cast<void*>(this), 1024);

    if (!result.ok())
    {
        m_ErrorMessage = result.msg();
    }

    return result.ok();
}

int BpfApi::PollEvents()
{
    // This poll cycle will read events from all CPU perf buffers and call the event callback for each event in the buffer.
    //  Each buffer is read until empty OR until the target timestamp is reached.  The probe will continue adding events to
    //  the queues during this process.  Since new events could be added to CPU queues that have already been read, and
    //  to queues yet to be read.  We could collect events in this pass that are "newer" than events in the CPU queue.
    //
    // To account for this we collect the events in a local list, sort them, check to queues again for any missed events
    //  which are older than the last one we have, sort them again, and finally send them to the client.
    //
    // We use the peek callback to stop adding events to the local list if we reach the target timestamp.  Otherwise on a
    //  really busy system we could collect so many events from one CPU that we have dificulty knowing exactly where to
    //  stop sending events.
    //
    // Note: This logic requires patches to BCC to provide the peek callback and a force perfbuffer read.
    //
    // This article has a good writeup of the problems.
    //   https://kinvolk.io/blog/2018/02/timing-issues-when-using-bpf-with-virtual-cpus/
    // Here is a reference implementation of the fix.  (I used this as a reference, but developed my own solution.)
    //  https://github.com/iovisor/gobpf/blob/65e4048660d6c4339ebae113ac55b1af6f01305d/elf/perf.go#L147
    if (!m_BPF)
    {
        return -1;
    }

    // Do we have events waiting to be sent from a previous read cycle
    auto events_waiting = !m_event_list.empty();

    if (m_did_leave_events)
    {
        // We left events on a CPU queue so we need to bypass the poll
        m_did_leave_events = false;
        m_BPF->read_perf_buffer("events");
    }
    else
    {
        auto timeout_ms = POLL_TIMEOUT_MS;
        if (events_waiting)
        {
            // We had events waiting, so force a very short sleep to give the probe the probe a chance to finish submitting
            //  events.  Also provide a very short timeout to the poll so that we don't hold onto events for very long.
            usleep(500);
            timeout_ms = 1;
        }
        m_did_leave_events = false;
        auto result = m_BPF->poll_perf_buffer("events", timeout_ms);

        if (result < 0)
        {
            return result;
        }
    }

    // Were events collected during this pass?
    //  This can be false even if events are available in the queuue since the peek function will cause us to stop reading
    //  events once we reach the target delta.
    auto collected_events = (m_event_count > 0);

    if (!m_event_list.empty())
    {
        if (collected_events)
        {
            // If we collected events during this cycle, than sort the list
            m_event_list.sort();
            m_timestamp_last  = m_event_list.back().GetEventTime();

            DEBUG_HARVEST({
                fprintf(stderr, "sorted ");
            });
        }

        DEBUG_HARVEST({
            #define TF(A) ((A) ? "true" : "false")
            fprintf(stderr, "%ld w:%s c:%s l:%s\n",
                m_event_list.size(),
                TF(events_waiting),
                TF(collected_events),
                TF(m_did_leave_events));
        });

        if (!collected_events)
        {
            // We have decided to harvest events.  We need to loop over all events in the list and send them to the target
            for (auto & data: m_event_list)
            {
                // Leave this here for future debugging
                DEBUG_ORDER({
                     uint64_t event_time = data.GetEventTime();
                     static uint64_t m_last_event_time = 0;
                     if (event_time < m_last_event_time)
                     {
                         auto ns = nanoseconds(m_last_event_time - event_time);
                         auto ms = duration_cast<milliseconds>(ns);
                         ns = ns - duration_cast<nanoseconds>(ms);
                         fprintf(stderr, "Event out of order (%ldms %ldns)\n",
                                     ms.count(), ns.count());
                     }
                     m_last_event_time = event_time;
                });

                m_eventCallbackFn(std::move(data));

            }

            // Erase the events that we sent
            m_event_list.clear();
            m_timestamp_last  = 0;
        }
    }
    m_event_count = 0;

    return 0;
}

bool BpfApi::GetKptrRestrict(long &kptr_restrict_value)
{
    auto fileHandle = open(m_kptr_restrict_path.c_str(), O_RDONLY);
    if (fileHandle <= 0)
    {
        return false;
    }

    size_t size = 32;
    unsigned char buffer[size] = {};
    auto bytesRead = read(fileHandle, buffer, size);
    close(fileHandle);

    if (!bytesRead || !buffer[0])
    {
        return false;
    }

    long value = strtol(reinterpret_cast<const char *>(buffer), nullptr, 10);
    if ((value == LONG_MIN || value == LONG_MAX) && errno == ERANGE)
    {
        return false;
    }

    kptr_restrict_value = value;

    return true;
}

void BpfApi::SetKptrRestrict(long value)
{
    size_t size = 32;
    char buffer[size] = {};
    int ret = snprintf(buffer, sizeof(buffer) -1, "%ld\n", value);
    if (ret <= 0 || !buffer[0])
    {
        return;
    }
    size = strlen(buffer);

    auto fileHandle = open(m_kptr_restrict_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fileHandle <= 0)
    {
        return;
    }

    IGNORE_UNUSED_RETURN_VALUE(write(fileHandle, buffer, size));
    close(fileHandle);
}

void BpfApi::LowerKptrRestrict()
{
    if (m_bracket_kptr_restrict)
    {
        SetKptrRestrict(1);
    }
}

void BpfApi::RaiseKptrRestrict()
{
    if (m_bracket_kptr_restrict)
    {
        SetKptrRestrict(m_kptr_restrict_orig);
    }
}

bool BpfApi::OnPeek(const bpf_probe::Data data)
{
    // This callback allows us to inspect the next event and signal BPF to stop reading from the current CPU queue
    //  * Always continue reading if this is the first cycle after we have cleared the list because m_timestamp_last is
    //    not valid.
    //  * Otherwise stop reading from this CPU if the event time is greater than the last timestamp.
    auto keep_collecting =  (!m_timestamp_last || (data.GetEventTime() <= m_timestamp_last));

    m_did_leave_events |= !keep_collecting;

    return keep_collecting;
}

void BpfApi::OnEvent(bpf_probe::Data data)
{
    // Keep a count of the events we capture during this poll cycle
    ++m_event_count;

    // Add the event to our internal event list
    m_event_list.emplace_back(std::move(data));
}

bool BpfApi::on_perf_peek(int cpu, void *cb_cookie, void *data, int data_size)
{
    auto bpfApi = static_cast<BpfApi*>(cb_cookie);
    if (bpfApi)
    {
        return bpfApi->OnPeek(static_cast<bpf_probe::data *>(data));
    }
    return false;
}

void BpfApi::on_perf_submit(void *cb_cookie, void *data, int data_size)
{
    auto bpfApi = static_cast<BpfApi*>(cb_cookie);
    if (bpfApi)
    {
        bpfApi->OnEvent(static_cast<bpf_probe::data *>(data));
    }
}
